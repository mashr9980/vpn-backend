from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from database import get_db
from schemas import VPNConfigCreate, VPNConfigResponse, VPNConfigFile
from models import User, Server, VPNConfig, IPAllocation
from dependencies import get_current_user
from utils.wireguard import generate_keypair
from utils.qr_generator import generate_qr_code
from utils.server_manager import server_manager
from utils.connection_monitor import connection_monitor
import logging

router = APIRouter()
logger = logging.getLogger(__name__)

@router.get("/configs", response_model=List[VPNConfigResponse])
def get_user_configs(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    configs = db.query(VPNConfig).filter(
        VPNConfig.user_id == current_user.id,
        VPNConfig.is_active == True
    ).all()
    return configs

@router.post("/create", response_model=VPNConfigResponse)
def create_vpn_config(config_data: VPNConfigCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    existing_config = db.query(VPNConfig).filter(
        VPNConfig.user_id == current_user.id,
        VPNConfig.server_id == config_data.server_id,
        VPNConfig.is_active == True
    ).first()
    
    if existing_config:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User already has an active configuration for this server"
        )
    
    server = db.query(Server).filter(
        Server.id == config_data.server_id,
        Server.is_active == True
    ).first()
    
    if not server:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Server not found"
        )
    
    private_key, public_key = generate_keypair()
    
    success, message, vpn_config = server_manager.create_tunnel_with_validation(
        db=db,
        server=server,
        user_id=current_user.id,
        private_key=private_key,
        public_key=public_key
    )
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=message
        )
    
    logger.info(f"Created VPN tunnel for user {current_user.username} on server {server.name}")
    return vpn_config

@router.get("/config/{config_id}/download", response_model=VPNConfigFile)
def download_config(config_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    vpn_config = db.query(VPNConfig).filter(
        VPNConfig.id == config_id,
        VPNConfig.user_id == current_user.id,
        VPNConfig.is_active == True
    ).first()
    
    if not vpn_config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="VPN configuration not found"
        )
    
    qr_code = generate_qr_code(vpn_config.config_content)
    
    return {
        "config_content": vpn_config.config_content,
        "qr_code": qr_code
    }

@router.delete("/config/{config_id}")
def delete_config(config_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    vpn_config = db.query(VPNConfig).filter(
        VPNConfig.id == config_id,
        VPNConfig.user_id == current_user.id,
        VPNConfig.is_active == True
    ).first()
    
    if not vpn_config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="VPN configuration not found"
        )
    
    success, message = server_manager.destroy_tunnel_with_validation(db, vpn_config)
    
    if success:
        logger.info(f"Deleted VPN tunnel for user {current_user.username}")
        return {"message": "VPN configuration deleted successfully"}
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=message
        )

@router.get("/config/{config_id}/status")
def get_config_status(config_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    vpn_config = db.query(VPNConfig).filter(
        VPNConfig.id == config_id,
        VPNConfig.user_id == current_user.id,
        VPNConfig.is_active == True
    ).first()
    
    if not vpn_config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="VPN configuration not found"
        )
    
    peer_status = connection_monitor.check_peer_connectivity(vpn_config.public_key)
    
    if peer_status:
        return {
            "config_id": config_id,
            "is_connected": peer_status.is_connected,
            "last_handshake": peer_status.last_handshake,
            "bytes_sent": peer_status.bytes_sent,
            "bytes_received": peer_status.bytes_received,
            "endpoint": peer_status.endpoint,
            "allocated_ip": vpn_config.allocated_ip
        }
    else:
        return {
            "config_id": config_id,
            "is_connected": False,
            "allocated_ip": vpn_config.allocated_ip,
            "message": "Peer not found in active connections"
        }

@router.post("/config/{config_id}/disconnect")
def force_disconnect(config_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    vpn_config = db.query(VPNConfig).filter(
        VPNConfig.id == config_id,
        VPNConfig.user_id == current_user.id,
        VPNConfig.is_active == True
    ).first()
    
    if not vpn_config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="VPN configuration not found"
        )
    
    success = connection_monitor.force_disconnect_peer(db, vpn_config.public_key)
    
    if success:
        return {"message": "VPN connection forcefully disconnected and tunnel removed"}
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to disconnect VPN"
        )