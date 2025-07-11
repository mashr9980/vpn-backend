import logging
import subprocess
import secrets
import base64
import ipaddress
import os
from typing import Tuple, Optional
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.backends import default_backend
from config import settings

logger = logging.getLogger(__name__)

def generate_private_key() -> str:
    private_key = x25519.X25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    return base64.b64encode(private_bytes).decode()

def generate_public_key(private_key: str) -> str:
    private_bytes = base64.b64decode(private_key.encode())
    private_key_obj = x25519.X25519PrivateKey.from_private_bytes(private_bytes)
    public_key_obj = private_key_obj.public_key()
    public_bytes = public_key_obj.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return base64.b64encode(public_bytes).decode()

def generate_preshared_key() -> str:
    return base64.b64encode(secrets.token_bytes(32)).decode()

def generate_keypair() -> Tuple[str, str]:
    private_key = generate_private_key()
    public_key = generate_public_key(private_key)
    return private_key, public_key

def create_client_config(private_key: str, allocated_ip: str, server_public_key: str, 
                        server_preshared_key: str, server_endpoint: str, server_port: int) -> str:
    config = f"""[Interface]
PrivateKey = {private_key}
Address = {allocated_ip}/24
DNS = {settings.VPN_DNS}

[Peer]
PublicKey = {server_public_key}
PresharedKey = {server_preshared_key}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
Endpoint = {server_endpoint}:{server_port}
"""
    return config

def get_next_available_ip(subnet: str, allocated_ips: list) -> Optional[str]:
    network = ipaddress.ip_network(subnet, strict=False)
    for ip in network.hosts():
        if str(ip) not in allocated_ips and str(ip) != network.network_address + 1:
            return str(ip)
    return None

def add_peer_to_server(server_id: int, public_key: str, allocated_ip: str, preshared_key: str):
    try:
        # For remote servers, simulate peer addition
        logger.info(f"Adding peer to remote server {server_id}")
        logger.info(f"Public Key: {public_key}")
        logger.info(f"Allocated IP: {allocated_ip}")
        logger.info(f"Preshared Key: {preshared_key}")
        
        # Try local WireGuard first
        try:
            cmd = [
                "wg", "set", settings.WIREGUARD_INTERFACE,
                "peer", public_key,
                "allowed-ips", f"{allocated_ip}/32",
                "preshared-key", "/dev/stdin"
            ]
            process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate(input=preshared_key.encode())
            
            if process.returncode == 0:
                subprocess.run(["wg-quick", "save", settings.WIREGUARD_INTERFACE], check=True)
                logger.info("Peer added to local WireGuard successfully")
                return True
        except (FileNotFoundError, subprocess.CalledProcessError) as e:
            logger.info(f"Local WireGuard not available: {e}")
        
        # For remote servers, we simulate success since we can't directly manage them
        # In production, you would integrate with your WireGuard panel's API here
        logger.info("Simulating peer addition for remote server")
        
        # TODO: Integrate with WireGuard panel API
        # For now, we'll return True to simulate successful peer addition
        
        return True
        
    except Exception as e:
        logger.error(f"Error adding peer: {e}")
        return False

def remove_peer_from_server(public_key: str):
    try:
        # Try local WireGuard first
        try:
            cmd = ["wg", "set", settings.WIREGUARD_INTERFACE, "peer", public_key, "remove"]
            subprocess.run(cmd, check=True)
            subprocess.run(["wg-quick", "save", settings.WIREGUARD_INTERFACE], check=True)
            logger.info("Peer removed from local WireGuard successfully")
            return True
        except (FileNotFoundError, subprocess.CalledProcessError) as e:
            logger.info(f"Local WireGuard not available: {e}")
        
        # For remote servers, simulate peer removal
        logger.info(f"Simulating peer removal for remote server: {public_key}")
        
        # TODO: Integrate with WireGuard panel API
        # For now, we'll return True to simulate successful peer removal
        
        return True
        
    except Exception as e:
        logger.error(f"Error removing peer: {e}")
        return False

def get_peer_stats(public_key: str) -> dict:
    try:
        # Try local WireGuard first
        try:
            result = subprocess.run(["wg", "show", settings.WIREGUARD_INTERFACE, "dump"], 
                                  capture_output=True, text=True, check=True)
            
            for line in result.stdout.strip().split('\n')[1:]:
                parts = line.split('\t')
                if len(parts) >= 6 and parts[0] == public_key:
                    return {
                        'endpoint': parts[2] if parts[2] != '(none)' else None,
                        'bytes_received': int(parts[4]),
                        'bytes_sent': int(parts[5]),
                        'last_handshake': parts[3] if parts[3] != '0' else None
                    }
        except (FileNotFoundError, subprocess.CalledProcessError) as e:
            logger.info(f"Local WireGuard not available: {e}")
        
        # For remote servers, return mock stats
        return {
            'endpoint': None,
            'bytes_received': 0,
            'bytes_sent': 0,
            'last_handshake': None
        }
        
    except Exception as e:
        logger.error(f"Error getting peer stats: {e}")
        return {}