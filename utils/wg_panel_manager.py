import requests
import json
import logging
import base64
import uuid
from typing import Dict, Optional, Tuple, List
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse
from datetime import datetime
import asyncio
import aiohttp

logger = logging.getLogger(__name__)

@dataclass
class WgEasyClient:
    id: str
    name: str
    enabled: bool
    address: str
    public_key: str
    created_at: datetime
    updated_at: datetime
    
@dataclass
class WgEasyPeerStatus:
    client_id: str
    last_handshake: Optional[datetime]
    bytes_received: int
    bytes_sent: int
    is_connected: bool

class WgEasyManager:
    def __init__(self, panel_url: str, password: str):
        self.panel_url = panel_url.rstrip('/')
        self.password = password
        self.session = None
        self.authenticated = False
        self.client_session = None
        
    def _get_sync_session(self) -> requests.Session:
        if not self.session:
            self.session = requests.Session()
            self.session.headers.update({
                'User-Agent': 'WireGuard-VPN-Backend/2.0',
                'Content-Type': 'application/json'
            })
            self.session.timeout = 30
        return self.session
    
    def _authenticate(self) -> bool:
        try:
            session = self._get_sync_session()
            
            # Create session with password
            auth_data = {"password": self.password}
            response = session.post(f"{self.panel_url}/api/session", json=auth_data)
            
            if response.status_code == 200:
                self.authenticated = True
                logger.info("Successfully authenticated with wg-easy panel")
                return True
            else:
                logger.error(f"Authentication failed: HTTP {response.status_code}")
                return False
            
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return False
    
    def test_connection(self) -> Tuple[bool, str]:
        try:
            if not self.authenticated:
                if not self._authenticate():
                    return False, "Authentication failed - check password"
            
            session = self._get_sync_session()
            
            # Test the known working endpoint
            try:
                response = session.get(f"{self.panel_url}/api/wireguard/client")
                if response.status_code == 200:
                    logger.info("Successfully connected using /api/wireguard/client endpoint")
                    return True, "Successfully connected to wg-easy panel"
                elif response.status_code == 401:
                    # Re-authenticate and try again
                    if self._authenticate():
                        response = session.get(f"{self.panel_url}/api/wireguard/client")
                        if response.status_code == 200:
                            return True, "Successfully connected after re-authentication"
                    return False, "Authentication failed after retry"
                else:
                    return False, f"API returned HTTP {response.status_code}"
            except Exception as e:
                return False, f"Connection error: {str(e)}"
                
        except requests.exceptions.ConnectionError:
            return False, "Cannot connect to wg-easy panel - check URL and network"
        except requests.exceptions.Timeout:
            return False, "Connection timeout to wg-easy panel"
        except Exception as e:
            return False, f"Connection error: {str(e)}"
    
    def create_client(self, name: str) -> Tuple[bool, Optional[WgEasyClient], str]:
        try:
            if not self.authenticated:
                if not self._authenticate():
                    return False, None, "Authentication failed"
            
            unique_name = f"{name}_{int(datetime.now().timestamp())}_{uuid.uuid4().hex[:8]}"
            
            session = self._get_sync_session()
            
            # Use the correct endpoint for creating clients
            create_data = {"name": unique_name}
            
            try:
                response = session.post(f"{self.panel_url}/api/wireguard/client", json=create_data)
                
                if response.status_code == 200:
                    response_data = response.json()
                    
                    if response_data.get("success"):
                        # Client created successfully, now get the client list to find our new client
                        success, clients, _ = self.list_clients()
                        if success:
                            # Find the newly created client by name
                            new_client = next((c for c in clients if c.name == unique_name), None)
                            if new_client:
                                logger.info(f"Created WireGuard client: {unique_name} (ID: {new_client.id})")
                                return True, new_client, "Client created successfully"
                        
                        # If we can't find the client in the list, create a basic response
                        wg_client = WgEasyClient(
                            id="unknown",
                            name=unique_name,
                            enabled=True,
                            address="",
                            public_key="",
                            created_at=datetime.now(),
                            updated_at=datetime.now()
                        )
                        return True, wg_client, "Client created successfully"
                    else:
                        return False, None, "Client creation failed"
                elif response.status_code == 401:
                    # Re-authenticate and try again
                    if self._authenticate():
                        response = session.post(f"{self.panel_url}/api/wireguard/client", json=create_data)
                        if response.status_code == 200:
                            response_data = response.json()
                            if response_data.get("success"):
                                return True, None, "Client created successfully after re-auth"
                    return False, None, "Re-authentication failed"
                else:
                    return False, None, f"Failed to create client: HTTP {response.status_code}"
                    
            except Exception as e:
                logger.error(f"Error creating client: {e}")
                return False, None, f"Error creating client: {str(e)}"
                
        except Exception as e:
            logger.error(f"Error creating client: {e}")
            return False, None, f"Error creating client: {str(e)}"
    
    def delete_client(self, client_id: str) -> Tuple[bool, str]:
        try:
            if not self.authenticated:
                if not self._authenticate():
                    return False, "Authentication failed"
            
            session = self._get_sync_session()
            response = session.delete(f"{self.panel_url}/api/wireguard/client/{client_id}")
            
            if response.status_code == 200:
                response_data = response.json()
                if response_data.get("success"):
                    logger.info(f"Deleted WireGuard client: {client_id}")
                    return True, "Client deleted successfully"
                else:
                    return False, "Client deletion failed"
            elif response.status_code == 404:
                return False, "Client not found"
            elif response.status_code == 401:
                self.authenticated = False
                if self._authenticate():
                    response = session.delete(f"{self.panel_url}/api/wireguard/client/{client_id}")
                    if response.status_code == 200:
                        return True, "Client deleted successfully after re-auth"
                return False, "Authentication failed"
            else:
                return False, f"Failed to delete client: HTTP {response.status_code}"
                
        except Exception as e:
            logger.error(f"Error deleting client {client_id}: {e}")
            return False, f"Error deleting client: {str(e)}"
    
    def get_client_config(self, client_id: str) -> Tuple[bool, Optional[str], str]:
        try:
            if not self.authenticated:
                if not self._authenticate():
                    return False, None, "Authentication failed"
            
            session = self._get_sync_session()
            response = session.get(f"{self.panel_url}/api/wireguard/client/{client_id}/configuration")
            
            if response.status_code == 200:
                config_content = response.text
                return True, config_content, "Configuration retrieved successfully"
            elif response.status_code == 404:
                return False, None, "Client not found"
            elif response.status_code == 401:
                self.authenticated = False
                if self._authenticate():
                    response = session.get(f"{self.panel_url}/api/wireguard/client/{client_id}/configuration")
                    if response.status_code == 200:
                        return True, response.text, "Configuration retrieved after re-auth"
                return False, None, "Authentication failed"
            else:
                return False, None, f"Failed to get config: HTTP {response.status_code}"
                
        except Exception as e:
            logger.error(f"Error getting config for client {client_id}: {e}")
            return False, None, f"Error getting config: {str(e)}"
    
    def get_client_qr_code(self, client_id: str) -> Tuple[bool, Optional[str], str]:
        try:
            if not self.authenticated:
                if not self._authenticate():
                    return False, None, "Authentication failed"
            
            session = self._get_sync_session()
            response = session.get(f"{self.panel_url}/api/wireguard/client/{client_id}/qrcode")
            
            if response.status_code == 200:
                qr_data = response.text
                return True, qr_data, "QR code retrieved successfully"
            elif response.status_code == 404:
                return False, None, "Client not found"
            elif response.status_code == 401:
                self.authenticated = False
                if self._authenticate():
                    response = session.get(f"{self.panel_url}/api/wireguard/client/{client_id}/qrcode")
                    if response.status_code == 200:
                        return True, response.text, "QR code retrieved after re-auth"
                return False, None, "Authentication failed"
            else:
                return False, None, f"Failed to get QR code: HTTP {response.status_code}"
                
        except Exception as e:
            logger.error(f"Error getting QR code for client {client_id}: {e}")
            return False, None, f"Error getting QR code: {str(e)}"
    
    def list_clients(self) -> Tuple[bool, List[WgEasyClient], str]:
        try:
            if not self.authenticated:
                if not self._authenticate():
                    return False, [], "Authentication failed"
            
            session = self._get_sync_session()
            
            try:
                response = session.get(f"{self.panel_url}/api/wireguard/client")
                
                if response.status_code == 200:
                    clients_data = response.json()
                    clients = []
                    
                    # Handle list response
                    if isinstance(clients_data, list):
                        data_list = clients_data
                    else:
                        return False, [], "Unexpected response format"
                    
                    for client_data in data_list:
                        wg_client = WgEasyClient(
                            id=client_data.get('id', ''),
                            name=client_data.get('name', ''),
                            enabled=client_data.get('enabled', True),
                            address=client_data.get('address', ''),
                            public_key=client_data.get('publicKey', ''),
                            created_at=datetime.now(),
                            updated_at=datetime.now()
                        )
                        clients.append(wg_client)
                    
                    return True, clients, f"Found {len(clients)} clients"
                elif response.status_code == 401:
                    # Re-authenticate and try again
                    if self._authenticate():
                        response = session.get(f"{self.panel_url}/api/wireguard/client")
                        if response.status_code == 200:
                            # Repeat the parsing logic
                            clients_data = response.json()
                            clients = []
                            for client_data in clients_data:
                                wg_client = WgEasyClient(
                                    id=client_data.get('id', ''),
                                    name=client_data.get('name', ''),
                                    enabled=client_data.get('enabled', True),
                                    address=client_data.get('address', ''),
                                    public_key=client_data.get('publicKey', ''),
                                    created_at=datetime.now(),
                                    updated_at=datetime.now()
                                )
                                clients.append(wg_client)
                            return True, clients, f"Found {len(clients)} clients after re-auth"
                    return False, [], "Re-authentication failed"
                else:
                    return False, [], f"Failed to list clients: HTTP {response.status_code}"
                    
            except Exception as e:
                logger.error(f"Error in list_clients: {e}")
                return False, [], f"Error listing clients: {str(e)}"
                
        except Exception as e:
            logger.error(f"Error listing clients: {e}")
            return False, [], f"Error listing clients: {str(e)}"
    
    def enable_client(self, client_id: str) -> Tuple[bool, str]:
        try:
            if not self.authenticated:
                if not self._authenticate():
                    return False, "Authentication failed"
            
            session = self._get_sync_session()
            response = session.post(f"{self.panel_url}/api/wireguard/client/{client_id}/enable")
            
            if response.status_code == 204:
                return True, "Client enabled successfully"
            elif response.status_code == 404:
                return False, "Client not found"
            else:
                return False, f"Failed to enable client: HTTP {response.status_code}"
                
        except Exception as e:
            return False, f"Error enabling client: {str(e)}"
    
    def disable_client(self, client_id: str) -> Tuple[bool, str]:
        try:
            if not self.authenticated:
                if not self._authenticate():
                    return False, "Authentication failed"
            
            session = self._get_sync_session()
            response = session.post(f"{self.panel_url}/api/wireguard/client/{client_id}/disable")
            
            if response.status_code == 204:
                return True, "Client disabled successfully"
            elif response.status_code == 404:
                return False, "Client not found"
            else:
                return False, f"Failed to disable client: HTTP {response.status_code}"
                
        except Exception as e:
            return False, f"Error disabling client: {str(e)}"
    
    def get_server_info(self) -> Tuple[bool, Dict, str]:
        try:
            if not self.authenticated:
                if not self._authenticate():
                    return False, {}, "Authentication failed"
            
            session = self._get_sync_session()
            response = session.get(f"{self.panel_url}/api/wireguard/server")
            
            if response.status_code == 200:
                server_info = response.json()
                return True, server_info, "Server info retrieved successfully"
            elif response.status_code == 401:
                self.authenticated = False
                return False, {}, "Authentication failed"
            else:
                return False, {}, f"Failed to get server info: HTTP {response.status_code}"
                
        except Exception as e:
            logger.error(f"Error getting server info: {e}")
            return False, {}, f"Error getting server info: {str(e)}"


class DynamicTunnelManager:
    def __init__(self, wg_manager: WgEasyManager):
        self.wg_manager = wg_manager
        self.active_tunnels: Dict[int, str] = {}
        self.tunnel_cleanup_delay = 300
        
    async def create_user_tunnel(self, user_id: int, username: str) -> Tuple[bool, Optional[Dict], str]:
        try:
            if user_id in self.active_tunnels:
                existing_client_id = self.active_tunnels[user_id]
                success, clients, _ = self.wg_manager.list_clients()
                if success and any(c.id == existing_client_id for c in clients):
                    return False, None, "User already has an active tunnel"
                else:
                    del self.active_tunnels[user_id]
            
            client_name = f"user_{username}_{user_id}"
            success, client, message = self.wg_manager.create_client(client_name)
            
            if not success:
                return False, None, message
            
            config_success, config_content, config_msg = self.wg_manager.get_client_config(client.id)
            if not config_success:
                self.wg_manager.delete_client(client.id)
                return False, None, f"Failed to get configuration: {config_msg}"
            
            qr_success, qr_code, qr_msg = self.wg_manager.get_client_qr_code(client.id)
            
            self.active_tunnels[user_id] = client.id
            
            tunnel_data = {
                'client_id': client.id,
                'client_name': client.name,
                'address': client.address,
                'public_key': client.public_key,
                'config_content': config_content,
                'qr_code': qr_code if qr_success else None,
                'created_at': client.created_at.isoformat(),
                'enabled': client.enabled
            }
            
            logger.info(f"Created dynamic tunnel for user {user_id} ({username}): {client.id}")
            return True, tunnel_data, "Tunnel created successfully"
            
        except Exception as e:
            logger.error(f"Error creating tunnel for user {user_id}: {e}")
            return False, None, f"Error creating tunnel: {str(e)}"
    
    async def destroy_user_tunnel(self, user_id: int) -> Tuple[bool, str]:
        try:
            if user_id not in self.active_tunnels:
                return False, "No active tunnel found for user"
            
            client_id = self.active_tunnels[user_id]
            
            success, message = self.wg_manager.delete_client(client_id)
            
            if success:
                del self.active_tunnels[user_id]
                logger.info(f"Destroyed tunnel for user {user_id}: {client_id}")
                return True, "Tunnel destroyed successfully"
            else:
                if "not found" in message.lower():
                    del self.active_tunnels[user_id]
                    return True, "Tunnel was already removed"
                return False, message
                
        except Exception as e:
            logger.error(f"Error destroying tunnel for user {user_id}: {e}")
            return False, f"Error destroying tunnel: {str(e)}"
    
    async def get_user_tunnel_status(self, user_id: int) -> Tuple[bool, Optional[Dict], str]:
        try:
            if user_id not in self.active_tunnels:
                return False, None, "No active tunnel"
            
            client_id = self.active_tunnels[user_id]
            
            success, clients, message = self.wg_manager.list_clients()
            if not success:
                return False, None, f"Error checking tunnel status: {message}"
            
            client = next((c for c in clients if c.id == client_id), None)
            if not client:
                del self.active_tunnels[user_id]
                return False, None, "Tunnel was removed externally"
            
            tunnel_info = {
                'client_id': client.id,
                'client_name': client.name,
                'address': client.address,
                'public_key': client.public_key,
                'enabled': client.enabled,
                'created_at': client.created_at.isoformat(),
                'updated_at': client.updated_at.isoformat()
            }
            
            return True, tunnel_info, "Tunnel is active"
            
        except Exception as e:
            logger.error(f"Error getting tunnel status for user {user_id}: {e}")
            return False, None, f"Error getting tunnel status: {str(e)}"
    
    async def cleanup_inactive_tunnels(self) -> int:
        try:
            if not self.active_tunnels:
                return 0
            
            success, clients, _ = self.wg_manager.list_clients()
            if not success:
                logger.error("Failed to get client list for cleanup")
                return 0
            
            current_client_ids = {c.id for c in clients}
            cleanup_count = 0
            
            stale_users = []
            for user_id, client_id in self.active_tunnels.items():
                if client_id not in current_client_ids:
                    stale_users.append(user_id)
            
            for user_id in stale_users:
                del self.active_tunnels[user_id]
                cleanup_count += 1
                logger.info(f"Cleaned up stale tunnel reference for user {user_id}")
            
            return cleanup_count
            
        except Exception as e:
            logger.error(f"Error during tunnel cleanup: {e}")
            return 0
    
    def get_active_tunnel_count(self) -> int:
        return len(self.active_tunnels)
    
    def get_user_tunnel_id(self, user_id: int) -> Optional[str]:
        return self.active_tunnels.get(user_id)


# if __name__ == "__main__":
#     import asyncio
    
#     async def test_wg_easy_integration():
#         wg_manager = WgEasyManager(
#             panel_url="http://74.208.112.39:51821",
#             password="123456789"
#         )
        
#         print("Testing connection to wg-easy panel...")
#         success, message = wg_manager.test_connection()
#         print(f"Connection test: {'✅ PASS' if success else '❌ FAIL'} - {message}")
        
#         if not success:
#             return
        
#         tunnel_manager = DynamicTunnelManager(wg_manager)
        
#         print("\nTesting dynamic tunnel creation...")
#         success, tunnel_data, message = await tunnel_manager.create_user_tunnel(
#             user_id=999, 
#             username="test_user"
#         )
#         print(f"Create tunnel: {'✅ PASS' if success else '❌ FAIL'} - {message}")
        
#         if success:
#             print(f"Tunnel created: {tunnel_data['client_name']}")
#             print(f"Client ID: {tunnel_data['client_id']}")
#             print(f"IP Address: {tunnel_data['address']}")
            
#             print("\nTesting tunnel status...")
#             has_tunnel, tunnel_info, status_msg = await tunnel_manager.get_user_tunnel_status(999)
#             print(f"Tunnel status: {'✅ ACTIVE' if has_tunnel else '❌ INACTIVE'} - {status_msg}")
            
#             print("\nTesting tunnel destruction...")
#             success, destroy_msg = await tunnel_manager.destroy_user_tunnel(999)
#             print(f"Destroy tunnel: {'✅ PASS' if success else '❌ FAIL'} - {destroy_msg}")
    
#     print("WireGuard wg-easy integration module loaded successfully!")
#     print("Use the WgEasyManager and DynamicTunnelManager classes in your application.")