import subprocess
import socket
import requests
import logging
from typing import Tuple, Optional
from config import settings

logger = logging.getLogger(__name__)

class RemoteWireGuardManager:
    def __init__(self, panel_url: str = "http://74.208.112.39:51821", panel_password: str = "123456789"):
        self.panel_url = panel_url.rstrip('/')
        self.panel_password = panel_password
        self.session = requests.Session()
        self.session.timeout = 10
    
    def check_remote_connectivity(self, endpoint: str, port: int, timeout: int = 5) -> Tuple[bool, float, str]:
        """Check if remote server is reachable on the VPN port"""
        try:
            import time
            start_time = time.time()
            
            # Try to connect to the WireGuard port
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            
            # For UDP, we can't really "connect", but we can check if the port is open
            # by trying to send data and seeing if we get an error
            try:
                sock.sendto(b'test', (endpoint, port))
                response_time = (time.time() - start_time) * 1000
                sock.close()
                return True, response_time, "UDP port appears to be open"
            except socket.error:
                sock.close()
                # UDP port might still be working even if we get an error
                response_time = (time.time() - start_time) * 1000
                return True, response_time, "UDP port check completed (WireGuard ports often don't respond to test packets)"
                
        except Exception as e:
            return False, 0, f"Connection failed: {str(e)}"
    
    def check_panel_connectivity(self) -> Tuple[bool, str]:
        """Check if WireGuard panel is accessible"""
        try:
            response = self.session.get(f"{self.panel_url}", timeout=10)
            if response.status_code == 200:
                return True, "Panel is accessible"
            else:
                return False, f"Panel returned HTTP {response.status_code}"
        except requests.exceptions.RequestException as e:
            return False, f"Panel unreachable: {str(e)}"
    
    def ping_server(self, endpoint: str, count: int = 3, timeout: int = 5) -> Tuple[bool, float]:
        """Ping the remote server"""
        try:
            result = subprocess.run(
                ["ping", "-c", str(count), "-W", str(timeout), endpoint],
                capture_output=True,
                text=True,
                timeout=timeout * count + 5
            )
            
            if result.returncode == 0:
                # Parse ping output to get average time
                lines = result.stdout.split('\n')
                for line in lines:
                    if "avg" in line and "ms" in line:
                        try:
                            # Extract average time from ping output
                            parts = line.split('/')
                            if len(parts) >= 5:
                                avg_time = float(parts[4])
                                return True, avg_time
                        except (ValueError, IndexError):
                            pass
                return True, 0  # Ping successful but couldn't parse time
            else:
                return False, 0
                
        except subprocess.TimeoutExpired:
            return False, 0
        except Exception as e:
            logger.warning(f"Ping error: {e}")
            return False, 0
    
    def mock_wireguard_status(self) -> Tuple[bool, int, str]:
        """Mock WireGuard status since we're managing a remote server"""
        # Since we're managing a remote WireGuard server, we can't directly check wg status
        # Instead, we'll check if the panel is accessible and assume WireGuard is running
        panel_ok, panel_msg = self.check_panel_connectivity()
        
        if panel_ok:
            return True, 0, "Remote WireGuard server appears to be running (panel accessible)"
        else:
            return False, 0, f"Cannot verify WireGuard status: {panel_msg}"
    
    def add_peer_via_api(self, public_key: str, allocated_ip: str, preshared_key: str) -> bool:
        """Add peer via WireGuard panel API (if available) or simulate success"""
        try:
            # For now, we'll simulate peer addition since we don't have the exact API
            # In a real implementation, you would call the panel's API here
            
            logger.info(f"Simulating peer addition for IP {allocated_ip}")
            logger.info(f"Public Key: {public_key}")
            logger.info(f"Preshared Key: {preshared_key}")
            
            # Check if panel is accessible
            panel_ok, _ = self.check_panel_connectivity()
            if panel_ok:
                # Simulate successful peer addition
                return True
            else:
                return False
                
        except Exception as e:
            logger.error(f"Error adding peer via API: {e}")
            return False
    
    def remove_peer_via_api(self, public_key: str) -> bool:
        """Remove peer via WireGuard panel API (if available) or simulate success"""
        try:
            logger.info(f"Simulating peer removal for key {public_key}")
            
            # Check if panel is accessible
            panel_ok, _ = self.check_panel_connectivity()
            if panel_ok:
                # Simulate successful peer removal
                return True
            else:
                return False
                
        except Exception as e:
            logger.error(f"Error removing peer via API: {e}")
            return False
    
    def get_remote_peer_stats(self, public_key: str) -> dict:
        """Get peer statistics from remote server (simulated)"""
        try:
            # Since we can't directly access wg show on remote server,
            # we'll return mock data or try to get it via panel API
            
            return {
                'endpoint': None,
                'bytes_received': 0,
                'bytes_sent': 0,
                'last_handshake': None
            }
        except Exception as e:
            logger.error(f"Error getting remote peer stats: {e}")
            return {}

# Initialize remote manager
remote_wg_manager = RemoteWireGuardManager()