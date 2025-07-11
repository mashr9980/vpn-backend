from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session
from database import get_db
from schemas import (
    VPNConfigCreate, VPNConfigResponse, VPNConfigFile, 
    VPNConnectionStatus, VPNResponse, SuccessResponse,
    PaginationParams, PaginatedResponse
)
from models import User, Server, VPNConfig, IPAllocation, UsageLog
from dependencies import get_current_user
from utils.wireguard import generate_keypair
from utils.server_manager import server_manager
from utils.connection_monitor import connection_monitor
from utils.qr_generator import generate_qr_code
from exceptions import (
    ResourceNotFoundError, ResourceConflictError, VPNConnectionError,
    ServerError, ValidationError
)
import logging
from datetime import datetime
from typing import List

router = APIRouter()
logger = logging.getLogger(__name__)

@router.get("/configs", response_model=PaginatedResponse)
async def get_user_configs(
    pagination: PaginationParams = Depends(),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        query = db.query(VPNConfig).filter(
            VPNConfig.user_id == current_user.id,
            VPNConfig.is_active == True
        )
        
        # Apply search filter if provided
        if pagination.search:
            search_term = f"%{pagination.search}%"
            query = query.join(Server).filter(
                Server.name.ilike(search_term) | 
                Server.location.ilike(search_term) |
                VPNConfig.allocated_ip.ilike(search_term)
            )
        
        # Get total count
        total = query.count()
        
        # Apply pagination
        offset = (pagination.page - 1) * pagination.limit
        configs = query.offset(offset).limit(pagination.limit).all()
        
        # Convert to response format
        config_list = []
        for config in configs:
            config_data = VPNConfigResponse.from_orm(config)
            config_list.append(config_data.dict())
        
        pages = (total + pagination.limit - 1) // pagination.limit
        
        return PaginatedResponse(
            status="success",
            message=f"Retrieved {len(config_list)} VPN configurations",
            data={
                "items": config_list,
                "total": total,
                "page": pagination.page,
                "limit": pagination.limit,
                "pages": pages
            }
        )
        
    except Exception as e:
        logger.error(f"Error retrieving VPN configs for user {current_user.id}: {str(e)}")
        raise Exception("Failed to retrieve VPN configurations")

@router.post("/create", response_model=VPNResponse, status_code=status.HTTP_201_CREATED)
async def create_vpn_tunnel(
    config_data: VPNConfigCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        # Validate server exists and is active
        server = db.query(Server).filter(
            Server.id == config_data.server_id,
            Server.is_active == True
        ).first()
        
        if not server:
            raise ResourceNotFoundError("Server", config_data.server_id)
        
        # Check if user already has an active configuration for this server
        existing_config = db.query(VPNConfig).filter(
            VPNConfig.user_id == current_user.id,
            VPNConfig.server_id == config_data.server_id,
            VPNConfig.is_active == True
        ).first()
        
        if existing_config:
            raise ResourceConflictError(
                f"You already have an active VPN configuration for server '{server.name}'",
                "vpn_config"
            )
        
        # Check server health before creating tunnel
        try:
            is_healthy, health = server_manager.is_server_healthy(server)
            if not is_healthy and not server.panel_url:
                raise ServerError(
                    f"Server '{server.name}' is not healthy: {health.error_message}",
                    server.id
                )
        except Exception as e:
            logger.warning(f"Server health check failed for {server.id}: {str(e)}")
        
        # Generate WireGuard keys
        private_key, public_key = generate_keypair()
        
        # Create tunnel with validation
        success, message, vpn_config = server_manager.create_tunnel_with_validation(
            db=db,
            server=server,
            user_id=current_user.id,
            private_key=private_key,
            public_key=public_key
        )
        
        if not success:
            raise VPNConnectionError(message)
        
        # Create usage log entry
        try:
            usage_log = UsageLog(
                user_id=current_user.id,
                vpn_config_id=vpn_config.id,
                bytes_sent=0,
                bytes_received=0,
                session_start=datetime.utcnow()
            )
            db.add(usage_log)
            db.commit()
        except Exception as e:
            logger.warning(f"Failed to create usage log: {str(e)}")
        
        # Prepare response
        config_response = VPNConfigResponse.from_orm(vpn_config)
        
        logger.info(f"VPN tunnel created for user {current_user.username} on server {server.name}")
        
        return VPNResponse(
            status="success",
            message="VPN tunnel created successfully",
            data={
                "config": config_response.dict(),
                "connection_info": {
                    "allocated_ip": vpn_config.allocated_ip,
                    "server_name": server.name,
                    "server_location": server.location,
                    "created_at": vpn_config.created_at.isoformat()
                }
            }
        )
        
    except (ResourceNotFoundError, ResourceConflictError, VPNConnectionError, ServerError):
        raise
    except Exception as e:
        logger.error(f"Error creating VPN tunnel: {str(e)}")
        db.rollback()
        raise Exception("Failed to create VPN tunnel. Please try again.")

@router.get("/config/{config_id}", response_model=VPNResponse)
async def get_vpn_config(
    config_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        vpn_config = db.query(VPNConfig).filter(
            VPNConfig.id == config_id,
            VPNConfig.user_id == current_user.id,
            VPNConfig.is_active == True
        ).first()
        
        if not vpn_config:
            raise ResourceNotFoundError("VPN Configuration", config_id)
        
        config_response = VPNConfigResponse.from_orm(vpn_config)
        
        return VPNResponse(
            status="success",
            message="VPN configuration retrieved successfully",
            data={
                "config": config_response.dict()
            }
        )
        
    except ResourceNotFoundError:
        raise
    except Exception as e:
        logger.error(f"Error retrieving VPN config {config_id}: {str(e)}")
        raise Exception("Failed to retrieve VPN configuration")

@router.get("/config/{config_id}/download", response_model=VPNConfigFile)
async def download_vpn_config(
    config_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        vpn_config = db.query(VPNConfig).filter(
            VPNConfig.id == config_id,
            VPNConfig.user_id == current_user.id,
            VPNConfig.is_active == True
        ).first()
        
        if not vpn_config:
            raise ResourceNotFoundError("VPN Configuration", config_id)
        
        # Generate QR code
        try:
            qr_code = generate_qr_code(vpn_config.config_content)
        except Exception as e:
            logger.error(f"Error generating QR code: {str(e)}")
            qr_code = ""
        
        return VPNConfigFile(
            config_content=vpn_config.config_content,
            qr_code=qr_code,
            server_info={
                "id": vpn_config.server.id,
                "name": vpn_config.server.name,
                "location": vpn_config.server.location,
                "endpoint": vpn_config.server.endpoint,
                "port": vpn_config.server.port
            },
            connection_info={
                "config_id": vpn_config.id,
                "allocated_ip": vpn_config.allocated_ip,
                "created_at": vpn_config.created_at.isoformat(),
                "is_active": vpn_config.is_active
            }
        )
        
    except ResourceNotFoundError:
        raise
    except Exception as e:
        logger.error(f"Error downloading VPN config {config_id}: {str(e)}")
        raise Exception("Failed to download VPN configuration")

@router.get("/config/{config_id}/status", response_model=VPNConnectionStatus)
async def get_connection_status(
    config_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        vpn_config = db.query(VPNConfig).filter(
            VPNConfig.id == config_id,
            VPNConfig.user_id == current_user.id,
            VPNConfig.is_active == True
        ).first()
        
        if not vpn_config:
            raise ResourceNotFoundError("VPN Configuration", config_id)
        
        # Check peer connectivity
        peer_status = connection_monitor.check_peer_connectivity(vpn_config.public_key)
        
        # Get latest usage log
        latest_usage = db.query(UsageLog).filter(
            UsageLog.vpn_config_id == config_id
        ).order_by(UsageLog.session_start.desc()).first()
        
        if peer_status:
            return VPNConnectionStatus(
                config_id=config_id,
                is_connected=peer_status.is_connected,
                allocated_ip=vpn_config.allocated_ip,
                bytes_sent=peer_status.bytes_sent,
                bytes_received=peer_status.bytes_received,
                last_handshake=peer_status.last_handshake,
                endpoint=peer_status.endpoint,
                connection_time=latest_usage.session_start if latest_usage else None
            )
        else:
            return VPNConnectionStatus(
                config_id=config_id,
                is_connected=False,
                allocated_ip=vpn_config.allocated_ip,
                bytes_sent=latest_usage.bytes_sent if latest_usage else 0,
                bytes_received=latest_usage.bytes_received if latest_usage else 0,
                last_handshake=latest_usage.last_handshake if latest_usage else None,
                endpoint=None,
                connection_time=latest_usage.session_start if latest_usage else None
            )
        
    except ResourceNotFoundError:
        raise
    except Exception as e:
        logger.error(f"Error getting connection status for config {config_id}: {str(e)}")
        raise Exception("Failed to get connection status")

@router.delete("/config/{config_id}", response_model=SuccessResponse)
async def disconnect_vpn(
    config_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        vpn_config = db.query(VPNConfig).filter(
            VPNConfig.id == config_id,
            VPNConfig.user_id == current_user.id,
            VPNConfig.is_active == True
        ).first()
        
        if not vpn_config:
            raise ResourceNotFoundError("VPN Configuration", config_id)
        
        # Store server name for response
        server_name = vpn_config.server.name
        allocated_ip = vpn_config.allocated_ip
        
        # Destroy tunnel with validation
        success, message = server_manager.destroy_tunnel_with_validation(db, vpn_config)
        
        if not success:
            raise VPNConnectionError(f"Failed to disconnect VPN: {message}")
        
        # Update usage log
        try:
            latest_usage = db.query(UsageLog).filter(
                UsageLog.vpn_config_id == config_id,
                UsageLog.session_end.is_(None)
            ).first()
            
            if latest_usage:
                latest_usage.session_end = datetime.utcnow()
                db.commit()
        except Exception as e:
            logger.warning(f"Failed to update usage log: {str(e)}")
        
        logger.info(f"VPN tunnel disconnected for user {current_user.username} from server {server_name}")
        
        return SuccessResponse(
            status="success",
            message="VPN disconnected successfully",
            data={
                "config_id": config_id,
                "server_name": server_name,
                "allocated_ip": allocated_ip,
                "disconnected_at": datetime.utcnow().isoformat()
            }
        )
        
    except (ResourceNotFoundError, VPNConnectionError):
        raise
    except Exception as e:
        logger.error(f"Error disconnecting VPN config {config_id}: {str(e)}")
        raise Exception("Failed to disconnect VPN")

@router.post("/config/{config_id}/force-disconnect", response_model=SuccessResponse)
async def force_disconnect_vpn(
    config_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        vpn_config = db.query(VPNConfig).filter(
            VPNConfig.id == config_id,
            VPNConfig.user_id == current_user.id,
            VPNConfig.is_active == True
        ).first()
        
        if not vpn_config:
            raise ResourceNotFoundError("VPN Configuration", config_id)
        
        # Force disconnect using connection monitor
        success = connection_monitor.force_disconnect_peer(db, vpn_config.public_key)
        
        if not success:
            raise VPNConnectionError("Failed to force disconnect VPN")
        
        logger.info(f"VPN tunnel force disconnected for user {current_user.username}")
        
        return SuccessResponse(
            status="success",
            message="VPN force disconnected successfully",
            data={
                "config_id": config_id,
                "action": "force_disconnect",
                "disconnected_at": datetime.utcnow().isoformat()
            }
        )
        
    except (ResourceNotFoundError, VPNConnectionError):
        raise
    except Exception as e:
        logger.error(f"Error force disconnecting VPN config {config_id}: {str(e)}")
        raise Exception("Failed to force disconnect VPN")

@router.get("/usage", response_model=PaginatedResponse)
async def get_usage_history(
    pagination: PaginationParams = Depends(),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        query = db.query(UsageLog).filter(UsageLog.user_id == current_user.id)
        
        # Get total count
        total = query.count()
        
        # Apply pagination and order by most recent
        offset = (pagination.page - 1) * pagination.limit
        usage_logs = query.order_by(UsageLog.session_start.desc()).offset(offset).limit(pagination.limit).all()
        
        # Convert to response format
        usage_list = []
        for log in usage_logs:
            duration_minutes = None
            if log.session_end:
                duration = log.session_end - log.session_start
                duration_minutes = int(duration.total_seconds() / 60)
            
            usage_list.append({
                "id": log.id,
                "bytes_sent": log.bytes_sent,
                "bytes_received": log.bytes_received,
                "last_handshake": log.last_handshake.isoformat() if log.last_handshake else None,
                "session_start": log.session_start.isoformat(),
                "session_end": log.session_end.isoformat() if log.session_end else None,
                "duration_minutes": duration_minutes
            })
        
        pages = (total + pagination.limit - 1) // pagination.limit
        
        return PaginatedResponse(
            status="success",
            message=f"Retrieved {len(usage_list)} usage records",
            data={
                "items": usage_list,
                "total": total,
                "page": pagination.page,
                "limit": pagination.limit,
                "pages": pages
            }
        )
        
    except Exception as e:
        logger.error(f"Error retrieving usage history for user {current_user.id}: {str(e)}")
        raise Exception("Failed to retrieve usage history")