from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List, Optional
from database import get_db
from schemas import VPNConfigResponse, VPNConfigFile, VPNTunnelRequest, DynamicTunnelResponse
from models import User, VPNConfig
from dependencies import get_current_user
from utils.wg_panel_manager import DynamicTunnelManager, WgEasyManager
from utils.qr_generator import generate_qr_code
from config import settings
import logging
import asyncio
from datetime import datetime

router = APIRouter()
logger = logging.getLogger(__name__)

# Initialize the wg-easy manager with your panel details
wg_easy_manager = WgEasyManager(
    panel_url=getattr(settings, 'WG_EASY_PANEL_URL', 'http://74.208.112.39:51821'),
    password=getattr(settings, 'WG_EASY_PASSWORD', '123456789')
)

# Initialize dynamic tunnel manager
tunnel_manager = DynamicTunnelManager(wg_easy_manager)

@router.get("/status")
async def get_vpn_status():
    """Get VPN service status"""
    try:
        # Test connection to wg-easy panel
        success, message = wg_easy_manager.test_connection()
        
        if success:
            # Get server info
            server_success, server_info, server_msg = wg_easy_manager.get_server_info()
            active_tunnels = tunnel_manager.get_active_tunnel_count()
            
            return {
                "status": "online",
                "panel_connection": "connected",
                "message": message,
                "active_tunnels": active_tunnels,
                "server_info": server_info if server_success else {},
                "last_check": datetime.utcnow().isoformat()
            }
        else:
            return {
                "status": "offline",
                "panel_connection": "disconnected", 
                "message": message,
                "active_tunnels": 0,
                "last_check": datetime.utcnow().isoformat()
            }
    except Exception as e:
        logger.error(f"Error getting VPN status: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get VPN status"
        )

@router.post("/tunnel/create", response_model=DynamicTunnelResponse)
async def create_dynamic_tunnel(
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Create a dynamic VPN tunnel for the current user.
    Automatically provisions a new WireGuard client on the wg-easy panel.
    """
    try:
        logger.info(f"Creating dynamic tunnel for user {current_user.username} (ID: {current_user.id})")
        
        # Check if user already has an active tunnel
        has_tunnel, tunnel_info, status_msg = await tunnel_manager.get_user_tunnel_status(current_user.id)
        
        if has_tunnel:
            logger.info(f"User {current_user.username} already has an active tunnel")
            return DynamicTunnelResponse(
                status="success",
                message="Active tunnel already exists",
                data={
                    "tunnel_exists": True,
                    "tunnel_info": tunnel_info,
                    "config_content": None,
                    "qr_code": None
                }
            )
        
        # Create new dynamic tunnel
        success, tunnel_data, message = await tunnel_manager.create_user_tunnel(
            user_id=current_user.id,
            username=current_user.username
        )
        
        if not success:
            logger.error(f"Failed to create tunnel for user {current_user.username}: {message}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to create VPN tunnel: {message}"
            )
        
        # Save tunnel info to database for tracking
        try:
            vpn_config = VPNConfig(
                user_id=current_user.id,
                server_id=1,  # Default server ID for wg-easy
                public_key=tunnel_data['public_key'],
                private_key="managed_by_wg_easy",  # Not stored locally
                allocated_ip=tunnel_data['address'],
                config_content=tunnel_data['config_content'],
                is_active=True
            )
            
            db.add(vpn_config)
            db.commit()
            db.refresh(vpn_config)
            
            logger.info(f"Saved tunnel info to database: config_id={vpn_config.id}")
            
        except Exception as db_error:
            logger.warning(f"Failed to save tunnel to database: {db_error}")
            # Don't fail the request if database save fails
        
        # Schedule automatic cleanup after user disconnects
        background_tasks.add_task(schedule_tunnel_cleanup, current_user.id)
        
        logger.info(f"Successfully created dynamic tunnel for user {current_user.username}")
        
        return DynamicTunnelResponse(
            status="success",
            message="Dynamic VPN tunnel created successfully",
            data={
                "tunnel_exists": True,
                "tunnel_info": {
                    "client_id": tunnel_data['client_id'],
                    "client_name": tunnel_data['client_name'],
                    "address": tunnel_data['address'],
                    "public_key": tunnel_data['public_key'],
                    "created_at": tunnel_data['created_at'],
                    "enabled": tunnel_data['enabled']
                },
                "config_content": tunnel_data['config_content'],
                "qr_code": tunnel_data['qr_code']
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error creating tunnel for user {current_user.username}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while creating the VPN tunnel"
        )

@router.delete("/tunnel/destroy")
async def destroy_dynamic_tunnel(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Destroy the current user's VPN tunnel.
    Removes the WireGuard client from the wg-easy panel.
    """
    try:
        logger.info(f"Destroying tunnel for user {current_user.username} (ID: {current_user.id})")
        
        # Destroy the tunnel
        success, message = await tunnel_manager.destroy_user_tunnel(current_user.id)
        
        if not success and "no active tunnel" not in message.lower():
            logger.error(f"Failed to destroy tunnel for user {current_user.username}: {message}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to destroy VPN tunnel: {message}"
            )
        
        # Clean up database record
        try:
            vpn_config = db.query(VPNConfig).filter(
                VPNConfig.user_id == current_user.id,
                VPNConfig.is_active == True
            ).first()
            
            if vpn_config:
                vpn_config.is_active = False
                db.commit()
                logger.info(f"Deactivated database record for user {current_user.username}")
                
        except Exception as db_error:
            logger.warning(f"Failed to update database: {db_error}")
        
        logger.info(f"Successfully destroyed tunnel for user {current_user.username}")
        
        return {
            "status": "success",
            "message": "VPN tunnel destroyed successfully",
            "data": {
                "tunnel_destroyed": True,
                "destroyed_at": datetime.utcnow().isoformat()
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error destroying tunnel for user {current_user.username}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while destroying the VPN tunnel"
        )

@router.get("/tunnel/status")
async def get_tunnel_status(current_user: User = Depends(get_current_user)):
    """
    Get the current user's tunnel status.
    """
    try:
        has_tunnel, tunnel_info, status_msg = await tunnel_manager.get_user_tunnel_status(current_user.id)
        
        return {
            "status": "success",
            "message": status_msg,
            "data": {
                "has_active_tunnel": has_tunnel,
                "tunnel_info": tunnel_info,
                "checked_at": datetime.utcnow().isoformat()
            }
        }
        
    except Exception as e:
        logger.error(f"Error getting tunnel status for user {current_user.username}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get tunnel status"
        )

@router.get("/tunnel/config")
async def get_tunnel_config(current_user: User = Depends(get_current_user)):
    """
    Get the current user's tunnel configuration and QR code.
    """
    try:
        # Check if user has an active tunnel
        has_tunnel, tunnel_info, status_msg = await tunnel_manager.get_user_tunnel_status(current_user.id)
        
        if not has_tunnel:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No active VPN tunnel found. Create a tunnel first."
            )
        
        client_id = tunnel_info['client_id']
        
        # Get configuration
        config_success, config_content, config_msg = wg_easy_manager.get_client_config(client_id)
        if not config_success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to get configuration: {config_msg}"
            )
        
        # Get QR code
        qr_success, qr_code, qr_msg = wg_easy_manager.get_client_qr_code(client_id)
        
        return {
            "status": "success",
            "message": "Configuration retrieved successfully",
            "data": {
                "config_content": config_content,
                "qr_code": qr_code if qr_success else None,
                "tunnel_info": tunnel_info,
                "downloaded_at": datetime.utcnow().isoformat()
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting config for user {current_user.username}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get tunnel configuration"
        )

@router.post("/tunnel/toggle")
async def toggle_tunnel(current_user: User = Depends(get_current_user)):
    """
    Enable or disable the current user's tunnel.
    """
    try:
        # Check if user has an active tunnel
        has_tunnel, tunnel_info, status_msg = await tunnel_manager.get_user_tunnel_status(current_user.id)
        
        if not has_tunnel:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No active VPN tunnel found"
            )
        
        client_id = tunnel_info['client_id']
        current_enabled = tunnel_info['enabled']
        
        # Toggle the tunnel
        if current_enabled:
            success, message = wg_easy_manager.disable_client(client_id)
            action = "disabled"
        else:
            success, message = wg_easy_manager.enable_client(client_id)
            action = "enabled"
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to {action} tunnel: {message}"
            )
        
        logger.info(f"Tunnel {action} for user {current_user.username}")
        
        return {
            "status": "success",
            "message": f"Tunnel {action} successfully",
            "data": {
                "enabled": not current_enabled,
                "action": action,
                "toggled_at": datetime.utcnow().isoformat()
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error toggling tunnel for user {current_user.username}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to toggle tunnel"
        )

# Background task functions
async def schedule_tunnel_cleanup(user_id: int):
    """
    Schedule automatic cleanup of inactive tunnels.
    This runs in the background and cleans up tunnels after a delay.
    """
    try:
        # Wait for 5 minutes before starting cleanup checks
        await asyncio.sleep(300)
        
        # Check periodically if tunnel is still active
        for _ in range(12):  # Check for 1 hour (12 * 5 minutes)
            has_tunnel, tunnel_info, _ = await tunnel_manager.get_user_tunnel_status(user_id)
            
            if not has_tunnel:
                logger.info(f"Tunnel for user {user_id} was already cleaned up")
                return
            
            # TODO: Add logic to check if client is actually connected
            # For now, we'll just wait and let manual cleanup handle it
            await asyncio.sleep(300)  # Wait 5 minutes
        
        logger.info(f"Automatic cleanup period completed for user {user_id}")
        
    except Exception as e:
        logger.error(f"Error in tunnel cleanup task for user {user_id}: {e}")

@router.post("/admin/cleanup")
async def cleanup_inactive_tunnels(current_user: User = Depends(get_current_user)):
    """
    Manual cleanup of inactive tunnels (admin function).
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    
    try:
        cleanup_count = await tunnel_manager.cleanup_inactive_tunnels()
        
        return {
            "status": "success",
            "message": f"Cleaned up {cleanup_count} inactive tunnels",
            "data": {
                "cleaned_up_count": cleanup_count,
                "cleanup_at": datetime.utcnow().isoformat()
            }
        }
        
    except Exception as e:
        logger.error(f"Error during manual cleanup: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to cleanup inactive tunnels"
        )

@router.get("/admin/tunnels")
async def list_all_tunnels(current_user: User = Depends(get_current_user)):
    """
    List all active tunnels (admin function).
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    
    try:
        success, clients, message = wg_easy_manager.list_clients()
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to get tunnel list: {message}"
            )
        
        tunnel_list = []
        for client in clients:
            tunnel_list.append({
                "client_id": client.id,
                "name": client.name,
                "enabled": client.enabled,
                "address": client.address,
                "public_key": client.public_key,
                "created_at": client.created_at.isoformat(),
                "updated_at": client.updated_at.isoformat()
            })
        
        return {
            "status": "success",
            "message": f"Found {len(tunnel_list)} tunnels",
            "data": {
                "tunnels": tunnel_list,
                "total_count": len(tunnel_list),
                "active_tunnels": tunnel_manager.get_active_tunnel_count(),
                "listed_at": datetime.utcnow().isoformat()
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error listing tunnels: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list tunnels"
        )

# Legacy endpoints for backward compatibility
@router.get("/configs", response_model=List[VPNConfigResponse])
def get_user_configs_legacy(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Legacy endpoint - get user configs from database"""
    configs = db.query(VPNConfig).filter(
        VPNConfig.user_id == current_user.id,
        VPNConfig.is_active == True
    ).all()
    return configs

@router.get("/config/{config_id}/download", response_model=VPNConfigFile)
def download_config_legacy(config_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Legacy endpoint - download config file"""
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
        "qr_code": qr_code,
        "server_info": {"name": "wg-easy Server"},
        "connection_info": {"address": vpn_config.allocated_ip}
    }