from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session
from database import get_db
from schemas import (
    ServerCreate, ServerResponse, ServerCreateFromPanel, 
    ServerListResponse, ServerHealthStatus, SuccessResponse,
    PaginationParams, PaginatedResponse
)
from models import Server, User, IPAllocation, VPNConfig
from dependencies import get_current_user, get_admin_user
from utils.wireguard import generate_keypair, generate_preshared_key
from utils.server_manager import server_manager
from utils.panel_manager import panel_manager
from exceptions import (
    ResourceNotFoundError, ResourceConflictError, ServerError, 
    PanelError, ValidationError
)
import ipaddress
from config import settings
import logging
from urllib.parse import urlparse
from typing import List

router = APIRouter()
logger = logging.getLogger(__name__)

@router.get("/", response_model=ServerListResponse)
async def get_servers(
    pagination: PaginationParams = Depends(),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        query = db.query(Server).filter(Server.is_active == True)
        
        # Apply search filter if provided
        if pagination.search:
            search_term = f"%{pagination.search}%"
            query = query.filter(
                Server.name.ilike(search_term) | 
                Server.location.ilike(search_term) |
                Server.endpoint.ilike(search_term)
            )
        
        # Get total count
        total = query.count()
        
        # Apply pagination
        offset = (pagination.page - 1) * pagination.limit
        servers = query.offset(offset).limit(pagination.limit).all()
        
        # Convert to response format
        server_list = [ServerResponse.from_orm(server) for server in servers]
        
        pages = (total + pagination.limit - 1) // pagination.limit
        
        return ServerListResponse(
            status="success",
            message=f"Retrieved {len(server_list)} servers",
            data={
                "servers": [server.dict() for server in server_list],
                "total": total,
                "page": pagination.page,
                "limit": pagination.limit,
                "pages": pages
            }
        )
        
    except Exception as e:
        logger.error(f"Error retrieving servers: {str(e)}")
        raise Exception("Failed to retrieve servers")

@router.post("/create-from-panel", response_model=ServerResponse, status_code=status.HTTP_201_CREATED)
async def create_server_from_panel(
    server_data: ServerCreateFromPanel,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    try:
        # Validate and normalize panel URL
        panel_url = server_data.panel_url.rstrip('/')
        if not panel_url.startswith(('http://', 'https://')):
            panel_url = f"http://{panel_url}"
        
        # Extract endpoint from panel URL
        try:
            parsed_url = urlparse(panel_url)
            endpoint = parsed_url.hostname
            if not endpoint:
                raise ValidationError("Invalid panel URL format")
        except Exception:
            raise ValidationError("Invalid panel URL format")
        
        # Check if server already exists
        existing_server = db.query(Server).filter(
            Server.endpoint == endpoint,
            Server.port == 51820
        ).first()
        
        if existing_server:
            raise ResourceConflictError(
                f"Server with endpoint {endpoint}:51820 already exists",
                "server"
            )
        
        # Test panel connection
        logger.info(f"Testing connection to WireGuard panel: {panel_url}")
        panel_accessible, error_msg = panel_manager.test_panel_connection(panel_url)
        
        if not panel_accessible:
            raise PanelError(f"Cannot connect to WireGuard panel: {error_msg}", panel_url)
        
        # Attempt panel authentication
        panel_success = panel_manager.add_panel(panel_url, server_data.name, server_data.password)
        
        # Get server info from panel or generate defaults
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
            
            logger.warning(f"Generated default configuration for {endpoint} (panel auth failed)")
        
        # Create server in database
        new_server = Server(
            name=server_data.name,
            location=server_data.location,
            endpoint=server_info['endpoint'],
            port=server_info['port'],
            public_key=server_info['public_key'],
            private_key=server_info['private_key'],
            preshared_key=server_info['preshared_key'],
            subnet=server_info['subnet'],
            panel_url=panel_url,
            panel_password=server_data.password,
            is_active=True
        )
        
        db.add(new_server)
        db.commit()
        db.refresh(new_server)
        
        # Populate IP pool
        try:
            populate_ip_pool(db, new_server.id, server_info['subnet'])
        except Exception as e:
            logger.error(f"Failed to populate IP pool: {str(e)}")
            db.delete(new_server)
            db.commit()
            raise Exception("Failed to initialize server IP pool")
        
        logger.info(f"Server '{server_data.name}' created successfully with ID: {new_server.id}")
        
        return ServerResponse.from_orm(new_server)
        
    except (ResourceConflictError, ValidationError, PanelError):
        raise
    except Exception as e:
        logger.error(f"Error creating server from panel: {str(e)}")
        db.rollback()
        raise Exception("Failed to create server. Please check your panel configuration.")

@router.post("/", response_model=ServerResponse, status_code=status.HTTP_201_CREATED)
async def create_server(
    server_data: ServerCreate,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    try:
        # Check if server already exists
        existing_server = db.query(Server).filter(
            Server.endpoint == server_data.endpoint,
            Server.port == server_data.port
        ).first()
        
        if existing_server:
            raise ResourceConflictError(
                f"Server with endpoint {server_data.endpoint}:{server_data.port} already exists",
                "server"
            )
        
        # Generate WireGuard keys
        private_key, public_key = generate_keypair()
        preshared_key = generate_preshared_key()
        
        # Create server
        new_server = Server(
            name=server_data.name,
            location=server_data.location,
            endpoint=server_data.endpoint,
            port=server_data.port,
            public_key=public_key,
            private_key=private_key,
            preshared_key=preshared_key,
            subnet=settings.VPN_SUBNET,
            panel_url=None,
            panel_password=None,
            is_active=True
        )
        
        db.add(new_server)
        db.commit()
        db.refresh(new_server)
        
        # Populate IP pool
        populate_ip_pool(db, new_server.id, settings.VPN_SUBNET)
        
        # Test server health
        try:
            health = server_manager.comprehensive_server_check(new_server)
            if not health.is_responsive:
                logger.warning(f"New server {new_server.name} health check failed: {health.error_message}")
        except Exception as e:
            logger.warning(f"Server health check failed: {str(e)}")
        
        logger.info(f"Server '{server_data.name}' created successfully with ID: {new_server.id}")
        
        return ServerResponse.from_orm(new_server)
        
    except ResourceConflictError:
        raise
    except Exception as e:
        logger.error(f"Error creating server: {str(e)}")
        db.rollback()
        raise Exception("Failed to create server")

@router.get("/{server_id}", response_model=ServerResponse)
async def get_server(
    server_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        server = db.query(Server).filter(
            Server.id == server_id, 
            Server.is_active == True
        ).first()
        
        if not server:
            raise ResourceNotFoundError("Server", server_id)
        
        return ServerResponse.from_orm(server)
        
    except ResourceNotFoundError:
        raise
    except Exception as e:
        logger.error(f"Error retrieving server {server_id}: {str(e)}")
        raise Exception("Failed to retrieve server")

@router.get("/{server_id}/health", response_model=ServerHealthStatus)
async def get_server_health(
    server_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        server = db.query(Server).filter(
            Server.id == server_id, 
            Server.is_active == True
        ).first()
        
        if not server:
            raise ResourceNotFoundError("Server", server_id)
        
        # Check server health
        is_healthy, health = server_manager.is_server_healthy(server)
        
        return ServerHealthStatus(
            server_id=server_id,
            is_healthy=is_healthy,
            response_time=health.response_time,
            wireguard_status=health.wireguard_status,
            peer_count=health.peer_count,
            last_check=health.last_check,
            error_message=health.error_message,
            panel_url=server.panel_url
        )
        
    except ResourceNotFoundError:
        raise
    except Exception as e:
        logger.error(f"Error checking server health {server_id}: {str(e)}")
        raise ServerError(f"Failed to check server health", server_id)

@router.post("/{server_id}/test-connection")
async def test_server_connection(
    server_id: int,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    try:
        server = db.query(Server).filter(Server.id == server_id).first()
        
        if not server:
            raise ResourceNotFoundError("Server", server_id)
        
        # Comprehensive server health check
        health = server_manager.comprehensive_server_check(server)
        
        # Test panel connection if available
        panel_status = None
        if server.panel_url:
            panel_accessible, panel_msg = panel_manager.test_panel_connection(server.panel_url)
            panel_status = {
                "accessible": panel_accessible,
                "message": panel_msg,
                "url": server.panel_url
            }
        
        return SuccessResponse(
            status="success",
            message="Server connection test completed",
            data={
                "server": {
                    "id": server.id,
                    "name": server.name,
                    "endpoint": f"{server.endpoint}:{server.port}"
                },
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
        )
        
    except ResourceNotFoundError:
        raise
    except Exception as e:
        logger.error(f"Error testing server connection {server_id}: {str(e)}")
        raise ServerError(f"Failed to test server connection", server_id)

@router.put("/{server_id}", response_model=ServerResponse)
async def update_server(
    server_id: int,
    server_data: ServerCreate,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    try:
        server = db.query(Server).filter(Server.id == server_id).first()
        
        if not server:
            raise ResourceNotFoundError("Server", server_id)
        
        # Check for conflicts with other servers
        existing_server = db.query(Server).filter(
            Server.endpoint == server_data.endpoint,
            Server.port == server_data.port,
            Server.id != server_id
        ).first()
        
        if existing_server:
            raise ResourceConflictError(
                f"Another server with endpoint {server_data.endpoint}:{server_data.port} already exists",
                "server"
            )
        
        # Update server fields
        server.name = server_data.name
        server.location = server_data.location
        server.endpoint = server_data.endpoint
        server.port = server_data.port
        
        db.commit()
        db.refresh(server)
        
        logger.info(f"Server {server_id} updated successfully")
        
        return ServerResponse.from_orm(server)
        
    except (ResourceNotFoundError, ResourceConflictError):
        raise
    except Exception as e:
        logger.error(f"Error updating server {server_id}: {str(e)}")
        db.rollback()
        raise Exception("Failed to update server")

@router.delete("/{server_id}", response_model=SuccessResponse)
async def delete_server(
    server_id: int,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    try:
        server = db.query(Server).filter(Server.id == server_id).first()
        
        if not server:
            raise ResourceNotFoundError("Server", server_id)
        
        # Check for active VPN configurations
        active_configs = db.query(VPNConfig).filter(
            VPNConfig.server_id == server_id,
            VPNConfig.is_active == True
        ).count()
        
        if active_configs > 0:
            raise ResourceConflictError(
                f"Cannot delete server with {active_configs} active VPN configurations. "
                "Please disconnect all users first.",
                "server"
            )
        
        # Soft delete (mark as inactive)
        server.is_active = False
        db.commit()
        
        logger.info(f"Server {server_id} ({server.name}) deactivated")
        
        return SuccessResponse(
            status="success",
            message=f"Server '{server.name}' has been deactivated",
            data={
                "server_id": server_id,
                "server_name": server.name,
                "deactivated_at": server.created_at.isoformat()
            }
        )
        
    except (ResourceNotFoundError, ResourceConflictError):
        raise
    except Exception as e:
        logger.error(f"Error deleting server {server_id}: {str(e)}")
        db.rollback()
        raise Exception("Failed to delete server")

@router.post("/{server_id}/activate", response_model=SuccessResponse)
async def activate_server(
    server_id: int,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    try:
        server = db.query(Server).filter(Server.id == server_id).first()
        
        if not server:
            raise ResourceNotFoundError("Server", server_id)
        
        server.is_active = True
        db.commit()
        
        logger.info(f"Server {server_id} ({server.name}) activated")
        
        return SuccessResponse(
            status="success",
            message=f"Server '{server.name}' has been activated",
            data={
                "server_id": server_id,
                "server_name": server.name,
                "activated_at": server.created_at.isoformat()
            }
        )
        
    except ResourceNotFoundError:
        raise
    except Exception as e:
        logger.error(f"Error activating server {server_id}: {str(e)}")
        db.rollback()
        raise Exception("Failed to activate server")

def populate_ip_pool(db: Session, server_id: int, subnet: str):
    """Populate IP allocation pool for a server"""
    try:
        network = ipaddress.ip_network(subnet, strict=False)
        ip_count = 0
        
        for ip in network.hosts():
            # Skip gateway IP (usually first IP)
            if str(ip) != str(network.network_address + 1):
                ip_allocation = IPAllocation(
                    server_id=server_id,
                    ip_address=str(ip),
                    is_allocated=False
                )
                db.add(ip_allocation)
                ip_count += 1
        
        db.commit()
        logger.info(f"Populated {ip_count} IP addresses for server {server_id}")
        
    except Exception as e:
        logger.error(f"Error populating IP pool for server {server_id}: {str(e)}")
        raise Exception("Failed to populate IP pool")