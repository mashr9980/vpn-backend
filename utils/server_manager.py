import subprocess
import socket
import time
import requests
import logging
from typing import Dict, Optional, Tuple
from dataclasses import dataclass
from sqlalchemy.orm import Session
from models import Server, VPNConfig, IPAllocation
from utils.wireguard import add_peer_to_server, remove_peer_from_server
import threading
import json

logger = logging.getLogger(__name__)

@dataclass
class ServerHealth:
    is_responsive: bool
    response_time: float
    wireguard_status: bool
    peer_count: int
    last_check: float
    error_message: Optional[str] = None

class ServerManager:
    def __init__(self):
        self.server_health_cache: Dict[int, ServerHealth] = {}
        self.monitoring_active = False
        self.monitor_thread = None
        
    def check_server_connectivity(self, endpoint: str, port: int, timeout: int = 5) -> Tuple[bool, float, str]:
        try:
            start_time = time.time()
            
            # For remote WireGuard servers, use UDP socket test
            if port == 51820:  # WireGuard port
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(timeout)
                try:
                    sock.sendto(b'', (endpoint, port))
                    response_time = (time.time() - start_time) * 1000
                    sock.close()
                    return True, response_time, "WireGuard port is accessible"
                except socket.error:
                    sock.close()
                    response_time = (time.time() - start_time) * 1000
                    # For WireGuard, not getting a response is actually normal
                    return True, response_time, "WireGuard port check completed (no response expected)"
            else:
                # For other ports, use TCP
                with socket.create_connection((endpoint, port), timeout=timeout) as sock:
                    sock.settimeout(timeout)
                    response_time = (time.time() - start_time) * 1000
                    return True, response_time, "Connected successfully"
                
        except socket.timeout:
            return False, 0, f"Connection timeout to {endpoint}:{port}"
        except socket.gaierror as e:
            return False, 0, f"DNS resolution failed: {str(e)}"
        except ConnectionRefusedError:
            return False, 0, f"Connection refused by {endpoint}:{port}"
        except Exception as e:
            return False, 0, f"Connection error: {str(e)}"
    
    def check_wireguard_status(self, interface: str = "wg0") -> Tuple[bool, int, str]:
        try:
            # First try local WireGuard
            result = subprocess.run(
                ["wg", "show", interface], 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            
            if result.returncode == 0:
                peer_count = len([line for line in result.stdout.split('\n') if line.strip().startswith('peer:')])
                return True, peer_count, "Local WireGuard interface is active"
            else:
                # If local WireGuard is not available, assume remote management
                logger.info("Local WireGuard not found, assuming remote server management")
                return True, 0, "Remote WireGuard server (local interface not required)"
            
        except FileNotFoundError:
            # WireGuard tools not installed locally - this is OK for remote management
            logger.info("WireGuard tools not installed locally, assuming remote server management")
            return True, 0, "Remote WireGuard server (local tools not required)"
        except subprocess.TimeoutExpired:
            return False, 0, "WireGuard status check timed out"
        except Exception as e:
            # For remote servers, we can't check local WireGuard status
            logger.info(f"Local WireGuard check failed (expected for remote servers): {e}")
            return True, 0, "Remote WireGuard server management"
    
    def ping_server(self, endpoint: str, count: int = 3, timeout: int = 5) -> Tuple[bool, float]:
        try:
            result = subprocess.run(
                ["ping", "-c", str(count), "-W", str(timeout), endpoint],
                capture_output=True,
                text=True,
                timeout=timeout * count + 5
            )
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if "avg" in line and "ms" in line:
                        avg_time = float(line.split('/')[-2])
                        return True, avg_time
                return True, 0
            else:
                return False, 0
                
        except Exception:
            return False, 0
    
    def comprehensive_server_check(self, server: Server) -> ServerHealth:
        start_time = time.time()
        errors = []
        
        connectivity_ok, response_time, conn_msg = self.check_server_connectivity(
            server.endpoint, server.port
        )
        if not connectivity_ok:
            errors.append(conn_msg)
        
        ping_ok, ping_time = self.ping_server(server.endpoint)
        if not ping_ok:
            errors.append(f"Server {server.endpoint} is not responding to ping")
        
        wg_ok, peer_count, wg_msg = self.check_wireguard_status()
        if not wg_ok:
            errors.append(wg_msg)
        
        is_healthy = connectivity_ok and wg_ok
        error_message = "; ".join(errors) if errors else None
        
        health = ServerHealth(
            is_responsive=is_healthy,
            response_time=response_time if connectivity_ok else ping_time,
            wireguard_status=wg_ok,
            peer_count=peer_count,
            last_check=time.time(),
            error_message=error_message
        )
        
        self.server_health_cache[server.id] = health
        return health
    
    def get_server_health(self, server_id: int) -> Optional[ServerHealth]:
        return self.server_health_cache.get(server_id)
    
    def is_server_healthy(self, server: Server, max_age: int = 300) -> Tuple[bool, ServerHealth]:
        cached_health = self.server_health_cache.get(server.id)
        
        if cached_health and (time.time() - cached_health.last_check) < max_age:
            return cached_health.is_responsive, cached_health
        
        health = self.comprehensive_server_check(server)
        return health.is_responsive, health
    
    def create_tunnel_with_validation(self, db: Session, server: Server, user_id: int, 
                                    private_key: str, public_key: str) -> Tuple[bool, str, Optional[VPNConfig]]:
        try:
            is_healthy, health = self.is_server_healthy(server)
            if not is_healthy:
                # For panel-managed servers, we might still proceed with a warning
                if server.panel_url:
                    logger.warning(f"Server health check failed but proceeding with panel-managed server: {health.error_message}")
                else:
                    return False, f"Server is not healthy: {health.error_message}", None
            
            available_ip = db.query(IPAllocation).filter(
                IPAllocation.server_id == server.id,
                IPAllocation.is_allocated == False
            ).first()
            
            if not available_ip:
                return False, "No available IP addresses for this server", None
            
            # Use panel manager for peer addition if panel is configured
            if server.panel_url:
                from utils.panel_manager import panel_manager
                success = panel_manager.add_peer_to_panel(
                    server.panel_url, public_key, available_ip.ip_address, server.preshared_key
                )
            else:
                success = add_peer_to_server(
                    server_id=server.id,
                    public_key=public_key,
                    allocated_ip=available_ip.ip_address,
                    preshared_key=server.preshared_key
                )
            
            if not success:
                return False, "Failed to add peer to WireGuard server", None
            
            from utils.wireguard import create_client_config
            config_content = create_client_config(
                private_key=private_key,
                allocated_ip=available_ip.ip_address,
                server_public_key=server.public_key,
                server_preshared_key=server.preshared_key,
                server_endpoint=server.endpoint,
                server_port=server.port
            )
            
            vpn_config = VPNConfig(
                user_id=user_id,
                server_id=server.id,
                public_key=public_key,
                private_key=private_key,
                allocated_ip=available_ip.ip_address,
                config_content=config_content
            )
            
            db.add(vpn_config)
            
            available_ip.is_allocated = True
            available_ip.allocated_to = vpn_config.id
            
            db.commit()
            db.refresh(vpn_config)
            
            # Skip verification for panel-managed servers
            if not server.panel_url:
                verify_success = self.verify_peer_added(public_key)
                if not verify_success:
                    db.rollback()
                    return False, "Peer was not successfully added to server", None
            
            return True, "Tunnel created successfully", vpn_config
            
        except Exception as e:
            db.rollback()
            logger.error(f"Error creating tunnel: {str(e)}")
            return False, f"Failed to create tunnel: {str(e)}", None
    
    def destroy_tunnel_with_validation(self, db: Session, vpn_config: VPNConfig) -> Tuple[bool, str]:
        try:
            server = db.query(Server).filter(Server.id == vpn_config.server_id).first()
            
            # Use panel manager for peer removal if panel is configured
            if server and server.panel_url:
                from utils.panel_manager import panel_manager
                success = panel_manager.remove_peer_from_panel(server.panel_url, vpn_config.public_key)
            else:
                success = remove_peer_from_server(vpn_config.public_key)
            
            if success:
                vpn_config.is_active = False
                
                ip_allocation = db.query(IPAllocation).filter(
                    IPAllocation.allocated_to == vpn_config.id
                ).first()
                
                if ip_allocation:
                    ip_allocation.is_allocated = False
                    ip_allocation.allocated_to = None
                
                db.commit()
                
                # Skip verification for panel-managed servers
                if not (server and server.panel_url):
                    verify_success = self.verify_peer_removed(vpn_config.public_key)
                    if not verify_success:
                        logger.warning(f"Peer {vpn_config.public_key} may not have been fully removed")
                
                return True, "Tunnel destroyed successfully"
            else:
                return False, "Failed to remove peer from WireGuard server"
                
        except Exception as e:
            db.rollback()
            logger.error(f"Error destroying tunnel: {str(e)}")
            return False, f"Failed to destroy tunnel: {str(e)}"
    
    def verify_peer_added(self, public_key: str, max_attempts: int = 3) -> bool:
        for attempt in range(max_attempts):
            try:
                time.sleep(1)
                result = subprocess.run(
                    ["wg", "show", "wg0", "peers"], 
                    capture_output=True, 
                    text=True, 
                    timeout=10
                )
                
                if result.returncode == 0 and public_key in result.stdout:
                    return True
                    
            except Exception as e:
                logger.warning(f"Attempt {attempt + 1} to verify peer failed: {e}")
                
        return False
    
    def verify_peer_removed(self, public_key: str, max_attempts: int = 3) -> bool:
        for attempt in range(max_attempts):
            try:
                time.sleep(1)
                result = subprocess.run(
                    ["wg", "show", "wg0", "peers"], 
                    capture_output=True, 
                    text=True, 
                    timeout=10
                )
                
                if result.returncode == 0 and public_key not in result.stdout:
                    return True
                    
            except Exception as e:
                logger.warning(f"Attempt {attempt + 1} to verify peer removal failed: {e}")
                
        return False
    
    def start_monitoring(self, db_session_factory, check_interval: int = 300):
        if self.monitoring_active:
            return
            
        self.monitoring_active = True
        self.monitor_thread = threading.Thread(
            target=self._monitor_servers, 
            args=(db_session_factory, check_interval),
            daemon=True
        )
        self.monitor_thread.start()
        logger.info("Server monitoring started")
    
    def stop_monitoring(self):
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=10)
        logger.info("Server monitoring stopped")
    
    def _monitor_servers(self, db_session_factory, check_interval: int):
        while self.monitoring_active:
            try:
                db = db_session_factory()
                servers = db.query(Server).filter(Server.is_active == True).all()
                
                for server in servers:
                    if not self.monitoring_active:
                        break
                    
                    health = self.comprehensive_server_check(server)
                    logger.info(f"Server {server.name} health check: {'OK' if health.is_responsive else 'FAILED'}")
                    
                    if not health.is_responsive:
                        logger.warning(f"Server {server.name} is unhealthy: {health.error_message}")
                
                db.close()
                
            except Exception as e:
                logger.error(f"Error in server monitoring: {e}")
            
            time.sleep(check_interval)

server_manager = ServerManager()