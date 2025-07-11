import subprocess
import time
import threading
import logging
from typing import Dict, Set, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from models import VPNConfig, UsageLog
from utils.server_manager import server_manager

logger = logging.getLogger(__name__)

@dataclass
class PeerStatus:
    public_key: str
    last_handshake: Optional[datetime]
    bytes_received: int
    bytes_sent: int
    endpoint: Optional[str]
    is_connected: bool
    last_seen: datetime

class ConnectionMonitor:
    def __init__(self):
        self.monitoring_active = False
        self.monitor_thread = None
        self.peer_status: Dict[str, PeerStatus] = {}
        self.disconnection_threshold = 300  # 5 minutes
        self.cleanup_enabled = True
        
    def get_active_peers(self) -> Dict[str, PeerStatus]:
        try:
            result = subprocess.run(
                ["wg", "show", "wg0", "dump"], 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            
            if result.returncode != 0:
                logger.error("Failed to get WireGuard status")
                return {}
            
            peers = {}
            lines = result.stdout.strip().split('\n')
            
            for line in lines[1:]:  # Skip header
                if not line.strip():
                    continue
                    
                parts = line.split('\t')
                if len(parts) >= 6:
                    public_key = parts[0]
                    preshared_key = parts[1]
                    endpoint = parts[2] if parts[2] != '(none)' else None
                    allowed_ips = parts[3]
                    last_handshake_timestamp = parts[4]
                    bytes_received = int(parts[5]) if parts[5] else 0
                    bytes_sent = int(parts[6]) if len(parts) > 6 and parts[6] else 0
                    
                    last_handshake = None
                    if last_handshake_timestamp and last_handshake_timestamp != '0':
                        try:
                            last_handshake = datetime.fromtimestamp(int(last_handshake_timestamp))
                        except (ValueError, OverflowError):
                            pass
                    
                    is_connected = self._is_peer_connected(last_handshake)
                    
                    peers[public_key] = PeerStatus(
                        public_key=public_key,
                        last_handshake=last_handshake,
                        bytes_received=bytes_received,
                        bytes_sent=bytes_sent,
                        endpoint=endpoint,
                        is_connected=is_connected,
                        last_seen=datetime.utcnow()
                    )
            
            return peers
            
        except Exception as e:
            logger.error(f"Error getting active peers: {e}")
            return {}
    
    def _is_peer_connected(self, last_handshake: Optional[datetime]) -> bool:
        if not last_handshake:
            return False
        
        time_since_handshake = datetime.utcnow() - last_handshake
        return time_since_handshake.total_seconds() < self.disconnection_threshold
    
    def check_peer_connectivity(self, public_key: str) -> Optional[PeerStatus]:
        peers = self.get_active_peers()
        return peers.get(public_key)
    
    def update_usage_stats(self, db: Session):
        try:
            active_peers = self.get_active_peers()
            
            for public_key, peer_status in active_peers.items():
                vpn_config = db.query(VPNConfig).filter(
                    VPNConfig.public_key == public_key,
                    VPNConfig.is_active == True
                ).first()
                
                if vpn_config:
                    usage_log = UsageLog(
                        user_id=vpn_config.user_id,
                        vpn_config_id=vpn_config.id,
                        bytes_sent=peer_status.bytes_sent,
                        bytes_received=peer_status.bytes_received,
                        last_handshake=peer_status.last_handshake
                    )
                    db.add(usage_log)
            
            db.commit()
            logger.debug(f"Updated usage stats for {len(active_peers)} peers")
            
        except Exception as e:
            logger.error(f"Error updating usage stats: {e}")
            db.rollback()
    
    def cleanup_disconnected_peers(self, db: Session):
        if not self.cleanup_enabled:
            return
            
        try:
            active_configs = db.query(VPNConfig).filter(VPNConfig.is_active == True).all()
            active_peers = self.get_active_peers()
            
            disconnected_count = 0
            for config in active_configs:
                peer_status = active_peers.get(config.public_key)
                
                if not peer_status or not peer_status.is_connected:
                    time_since_created = datetime.utcnow() - config.created_at
                    
                    if time_since_created.total_seconds() > self.disconnection_threshold:
                        if peer_status and peer_status.last_handshake:
                            time_since_handshake = datetime.utcnow() - peer_status.last_handshake
                            if time_since_handshake.total_seconds() > self.disconnection_threshold:
                                self._cleanup_peer(db, config)
                                disconnected_count += 1
                        elif time_since_created.total_seconds() > self.disconnection_threshold * 2:
                            self._cleanup_peer(db, config)
                            disconnected_count += 1
            
            if disconnected_count > 0:
                logger.info(f"Cleaned up {disconnected_count} disconnected peers")
                
        except Exception as e:
            logger.error(f"Error in cleanup: {e}")
    
    def _cleanup_peer(self, db: Session, vpn_config: VPNConfig):
        try:
            success, message = server_manager.destroy_tunnel_with_validation(db, vpn_config)
            if success:
                logger.info(f"Auto-cleaned up tunnel for user {vpn_config.user_id}")
            else:
                logger.warning(f"Failed to auto-cleanup tunnel: {message}")
        except Exception as e:
            logger.error(f"Error cleaning up peer {vpn_config.public_key}: {e}")
    
    def force_disconnect_peer(self, db: Session, public_key: str) -> bool:
        try:
            vpn_config = db.query(VPNConfig).filter(
                VPNConfig.public_key == public_key,
                VPNConfig.is_active == True
            ).first()
            
            if vpn_config:
                success, message = server_manager.destroy_tunnel_with_validation(db, vpn_config)
                return success
            return False
            
        except Exception as e:
            logger.error(f"Error force disconnecting peer: {e}")
            return False
    
    def get_connection_stats(self) -> Dict:
        try:
            active_peers = self.get_active_peers()
            connected_count = sum(1 for peer in active_peers.values() if peer.is_connected)
            
            total_bytes_sent = sum(peer.bytes_sent for peer in active_peers.values())
            total_bytes_received = sum(peer.bytes_received for peer in active_peers.values())
            
            return {
                "total_peers": len(active_peers),
                "connected_peers": connected_count,
                "disconnected_peers": len(active_peers) - connected_count,
                "total_bytes_sent": total_bytes_sent,
                "total_bytes_received": total_bytes_received,
                "last_updated": datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"Error getting connection stats: {e}")
            return {}
    
    def start_monitoring(self, db_session_factory, check_interval: int = 60):
        if self.monitoring_active:
            return
            
        self.monitoring_active = True
        self.monitor_thread = threading.Thread(
            target=self._monitor_connections,
            args=(db_session_factory, check_interval),
            daemon=True
        )
        self.monitor_thread.start()
        logger.info("Connection monitoring started")
    
    def stop_monitoring(self):
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=10)
        logger.info("Connection monitoring stopped")
    
    def _monitor_connections(self, db_session_factory, check_interval: int):
        cycle_count = 0
        
        while self.monitoring_active:
            try:
                db = db_session_factory()
                
                self.update_usage_stats(db)
                
                if cycle_count % 5 == 0:  # Cleanup every 5 cycles
                    self.cleanup_disconnected_peers(db)
                
                active_peers = self.get_active_peers()
                self.peer_status.update(active_peers)
                
                connected_count = sum(1 for peer in active_peers.values() if peer.is_connected)
                logger.debug(f"Monitoring: {connected_count}/{len(active_peers)} peers connected")
                
                db.close()
                cycle_count += 1
                
            except Exception as e:
                logger.error(f"Error in connection monitoring: {e}")
            
            time.sleep(check_interval)

connection_monitor = ConnectionMonitor()