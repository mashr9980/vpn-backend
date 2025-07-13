from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from database import get_db
from schemas import ServerCreate, ServerResponse, ServerCreateFromPanel
from models import Server, User, IPAllocation, VPNConfig
from dependencies import get_current_user, get_admin_user
from utils.wireguard import generate_keypair, generate_preshared_key
from utils.server_manager import server_manager
from utils.panel_manager import panel_manager
import ipaddress
from config import settings
import logging
from urllib.parse import urlparse

router = APIRouter()
logger = logging.getLogger(__name__)

@router.get("/", response_model=List[ServerResponse])
def get_servers(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    servers = db.query(Server).filter(Server.is_active == True).all()
    return servers

@router.post("/create-from-panel", response_model=ServerResponse)
def create_server_from_panel(
    server_data: ServerCreateFromPanel, 
    db: Session = Depends(get_db), 
    admin_user: User = Depends(get_admin_user)
):
    """Create server by connecting to WireGuard panel with URL, name, and password"""
    try:
        # Validate and normalize panel URL
        panel_url = server_data.panel_url.rstrip('/')
        if not panel_url.startswith(('http://', 'https://')):
            panel_url = f"http://{panel_url}"
        
        # Extract endpoint from panel URL
        parsed_url = urlparse(panel_url)
        endpoint = parsed_url.hostname
        
        if not endpoint:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid panel URL"
            )
        
        # Check if server already exists
        existing_server = db.query(Server).filter(
            Server.endpoint == endpoint,
            Server.port == 51820
        ).first()
        
        if existing_server:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Server with endpoint {endpoint}:51820 already exists"
            )
        
        # Test panel connection and authenticate
        logger.info(f"Connecting to WireGuard panel: {panel_url}")
        panel_success = panel_manager.add_panel(panel_url, server_data.name, server_data.password)
        
        if not panel_success:
            # Try manual connection test
            panel_accessible, error_msg = panel_manager.test_panel_connection(panel_url)
            if not panel_accessible:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Cannot connect to WireGuard panel: {error_msg}"
                )
            
            # Panel is accessible but authentication failed, proceed with default setup
            logger.warning(f"Panel authentication failed, using default configuration")
        
        # Get server info from panel or use defaults
        server_info = panel_manager.get_panel_info(panel_url)
        
        if not server_info:
            # Generate default configuration
            private_key, public_key = generate_keypair()
            preshared_key = generate_preshared_key()
            
            server_info = {
                'endpoint': endpoint,
                'port': 51820,
                'public_key': public_key,
                'private_key': private_key,
                'preshared_key': preshared_key,
                'subnet': '10.8.0.0/24'
            }
            
            logger.info(f"Generated default configuration for {endpoint}")
        
        # Create server in database
        db_server = Server(
            name=server_data.name,
            location=server_data.location,
            endpoint=server_info['endpoint'],
            port=server_info['port'],
            public_key=server_info['public_key'],
            private_key=server_info['private_key'],
            preshared_key=server_info['preshared_key'],
            subnet=server_info['subnet'],
            panel_url=panel_url,
            panel_password=server_data.password
        )
        
        db.add(db_server)
        db.commit()
        db.refresh(db_server)
        
        # Populate IP pool
        populate_ip_pool(db, db_server.id, server_info['subnet'])
        
        logger.info(f"Server '{server_data.name}' created successfully with ID: {db_server.id}")
        
        return db_server
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating server from panel: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create server: {str(e)}"
        )

@router.post("/", response_model=ServerResponse)
def create_server(server: ServerCreate, db: Session = Depends(get_db), admin_user: User = Depends(get_admin_user)):
    existing_server = db.query(Server).filter(
        Server.endpoint == server.endpoint,
        Server.port == server.port
    ).first()
    
    if existing_server:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Server with this endpoint and port already exists"
        )
    
    private_key, public_key = generate_keypair()
    preshared_key = generate_preshared_key()
    
    db_server = Server(
        name=server.name,
        location=server.location,
        endpoint=server.endpoint,
        port=server.port,
        public_key=public_key,
        private_key=private_key,
        preshared_key=preshared_key,
        subnet=settings.VPN_SUBNET,
        panel_url=None,
        panel_password=None
    )
    db.add(db_server)
    db.commit()
    db.refresh(db_server)
    
    populate_ip_pool(db, db_server.id, settings.VPN_SUBNET)
    
    health = server_manager.comprehensive_server_check(db_server)
    if not health.is_responsive:
        logger.warning(f"New server {db_server.name} is not responding: {health.error_message}")
    
    return db_server

@router.get("/{server_id}", response_model=ServerResponse)
def get_server(server_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    server = db.query(Server).filter(Server.id == server_id, Server.is_active == True).first()
    if not server:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Server not found"
        )
    return server

@router.get("/{server_id}/health")
def get_server_health(server_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    server = db.query(Server).filter(Server.id == server_id, Server.is_active == True).first()
    if not server:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Server not found"
        )
    
    is_healthy, health = server_manager.is_server_healthy(server)
    
    return {
        "server_id": server_id,
        "is_healthy": is_healthy,
        "response_time": health.response_time,
        "wireguard_status": health.wireguard_status,
        "peer_count": health.peer_count,
        "last_check": health.last_check,
        "error_message": health.error_message,
        "panel_url": server.panel_url
    }

@router.post("/{server_id}/test-connection")
def test_server_connection(server_id: int, db: Session = Depends(get_db), admin_user: User = Depends(get_admin_user)):
    server = db.query(Server).filter(Server.id == server_id).first()
    if not server:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Server not found"
        )
    
    health = server_manager.comprehensive_server_check(server)
    
    # Also test panel connection if available
    panel_status = None
    if server.panel_url:
        panel_accessible, panel_msg = panel_manager.test_panel_connection(server.panel_url)
        panel_status = {
            "accessible": panel_accessible,
            "message": panel_msg
        }
    
    return {
        "server_name": server.name,
        "endpoint": f"{server.endpoint}:{server.port}",
        "connectivity_test": {
            "is_responsive": health.is_responsive,
            "response_time_ms": health.response_time,
            "error_message": health.error_message
        },
        "wireguard_test": {
            "status": health.wireguard_status,
            "peer_count": health.peer_count
        },
        "panel_test": panel_status,
        "overall_health": health.is_responsive and health.wireguard_status,
        "timestamp": health.last_check
    }

@router.delete("/{server_id}")
def delete_server(server_id: int, db: Session = Depends(get_db), admin_user: User = Depends(get_admin_user)):
    server = db.query(Server).filter(Server.id == server_id).first()
    if not server:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Server not found"
        )
    
    active_configs = db.query(VPNConfig).filter(
        VPNConfig.server_id == server_id,
        VPNConfig.is_active == True
    ).count()
    
    if active_configs > 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot delete server with {active_configs} active VPN configurations"
        )
    
    server.is_active = False
    db.commit()
    
    return {"message": f"Server {server.name} has been deactivated"}

def populate_ip_pool(db: Session, server_id: int, subnet: str):
    network = ipaddress.ip_network(subnet, strict=False)
    for ip in network.hosts():
        if str(ip) != str(network.network_address + 1):
            ip_allocation = IPAllocation(
                server_id=server_id,
                ip_address=str(ip),
                is_allocated=False
            )
            db.add(ip_allocation)
    db.commit()