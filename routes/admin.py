from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from database import get_db
from schemas import AdminUserResponse, VPNConfigResponse, UsageLogResponse, ConnectionStatsResponse
from models import User, VPNConfig, UsageLog, IPAllocation
from dependencies import get_admin_user
from utils.wireguard import get_peer_stats
from utils.server_manager import server_manager
from utils.connection_monitor import connection_monitor
from datetime import datetime
import logging

router = APIRouter()
logger = logging.getLogger(__name__)

@router.get("/users", response_model=List[AdminUserResponse])
def get_all_users(db: Session = Depends(get_db), admin_user: User = Depends(get_admin_user)):
    users = db.query(User).all()
    return users

@router.get("/configs", response_model=List[VPNConfigResponse])
def get_all_configs(db: Session = Depends(get_db), admin_user: User = Depends(get_admin_user)):
    configs = db.query(VPNConfig).filter(VPNConfig.is_active == True).all()
    return configs

@router.delete("/user/{user_id}/revoke")
def revoke_user_access(user_id: int, db: Session = Depends(get_db), admin_user: User = Depends(get_admin_user)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    vpn_configs = db.query(VPNConfig).filter(
        VPNConfig.user_id == user_id,
        VPNConfig.is_active == True
    ).all()
    
    revoked_count = 0
    for config in vpn_configs:
        success, message = server_manager.destroy_tunnel_with_validation(db, config)
        if success:
            revoked_count += 1
        else:
            logger.warning(f"Failed to revoke config {config.id}: {message}")
    
    user.is_active = False
    db.commit()
    
    return {"message": f"Revoked access for user {user.username}. {revoked_count} tunnels removed."}

@router.post("/user/{user_id}/activate")
def activate_user(user_id: int, db: Session = Depends(get_db), admin_user: User = Depends(get_admin_user)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    user.is_active = True
    db.commit()
    
    return {"message": f"Activated user {user.username}"}

@router.get("/usage", response_model=List[UsageLogResponse])
def get_usage_stats(db: Session = Depends(get_db), admin_user: User = Depends(get_admin_user)):
    usage_logs = db.query(UsageLog).order_by(UsageLog.session_start.desc()).limit(100).all()
    return usage_logs

@router.post("/sync-peer-stats")
def sync_peer_stats(db: Session = Depends(get_db), admin_user: User = Depends(get_admin_user)):
    try:
        connection_monitor.update_usage_stats(db)
        return {"message": "Peer statistics synced successfully"}
    except Exception as e:
        logger.error(f"Failed to sync peer stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to sync peer statistics"
        )

@router.get("/connection-stats", response_model=ConnectionStatsResponse)
def get_connection_stats(admin_user: User = Depends(get_admin_user)):
    stats = connection_monitor.get_connection_stats()
    if not stats:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve connection statistics"
        )
    return stats

@router.post("/cleanup-disconnected")
def cleanup_disconnected_peers(db: Session = Depends(get_db), admin_user: User = Depends(get_admin_user)):
    try:
        connection_monitor.cleanup_disconnected_peers(db)
        return {"message": "Disconnected peers cleanup completed"}
    except Exception as e:
        logger.error(f"Failed to cleanup disconnected peers: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to cleanup disconnected peers"
        )

@router.delete("/config/{config_id}/force-delete")
def force_delete_config(config_id: int, db: Session = Depends(get_db), admin_user: User = Depends(get_admin_user)):
    vpn_config = db.query(VPNConfig).filter(VPNConfig.id == config_id).first()
    if not vpn_config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="VPN configuration not found"
        )
    
    success, message = server_manager.destroy_tunnel_with_validation(db, vpn_config)
    
    if success:
        return {"message": f"Configuration {config_id} forcefully deleted"}
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete configuration: {message}"
        )

@router.get("/server-health")
def get_all_server_health(db: Session = Depends(get_db), admin_user: User = Depends(get_admin_user)):
    from models import Server
    servers = db.query(Server).filter(Server.is_active == True).all()
    
    health_reports = []
    for server in servers:
        is_healthy, health = server_manager.is_server_healthy(server)
        health_reports.append({
            "server_id": server.id,
            "server_name": server.name,
            "endpoint": f"{server.endpoint}:{server.port}",
            "is_healthy": is_healthy,
            "response_time": health.response_time,
            "wireguard_status": health.wireguard_status,
            "peer_count": health.peer_count,
            "last_check": health.last_check,
            "error_message": health.error_message
        })
    
    return {"servers": health_reports, "total_servers": len(servers)}

@router.post("/monitoring/start")
def start_monitoring(db: Session = Depends(get_db), admin_user: User = Depends(get_admin_user)):
    from database import SessionLocal
    
    try:
        server_manager.start_monitoring(SessionLocal)
        connection_monitor.start_monitoring(SessionLocal)
        return {"message": "Monitoring services started successfully"}
    except Exception as e:
        logger.error(f"Failed to start monitoring: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to start monitoring services"
        )

@router.post("/monitoring/stop")
def stop_monitoring(admin_user: User = Depends(get_admin_user)):
    try:
        server_manager.stop_monitoring()
        connection_monitor.stop_monitoring()
        return {"message": "Monitoring services stopped successfully"}
    except Exception as e:
        logger.error(f"Failed to stop monitoring: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to stop monitoring services"
        )