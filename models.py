from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Text, BigInteger
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    vpn_configs = relationship("VPNConfig", back_populates="user")
    usage_logs = relationship("UsageLog", back_populates="user")

class Server(Base):
    __tablename__ = "servers"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    location = Column(String, nullable=False)
    endpoint = Column(String, nullable=False)
    port = Column(Integer, nullable=False)
    public_key = Column(String, nullable=False)
    private_key = Column(String, nullable=False)
    preshared_key = Column(String, nullable=False)
    subnet = Column(String, nullable=False)
    panel_url = Column(String, nullable=True)
    panel_password = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    vpn_configs = relationship("VPNConfig", back_populates="server")

class VPNConfig(Base):
    __tablename__ = "vpn_configs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    server_id = Column(Integer, ForeignKey("servers.id"), nullable=False)
    public_key = Column(String, nullable=False)
    private_key = Column(String, nullable=False)
    allocated_ip = Column(String, nullable=False)
    config_content = Column(Text, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    user = relationship("User", back_populates="vpn_configs")
    server = relationship("Server", back_populates="vpn_configs")
    usage_logs = relationship("UsageLog", back_populates="vpn_config")

class UsageLog(Base):
    __tablename__ = "usage_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    vpn_config_id = Column(Integer, ForeignKey("vpn_configs.id"), nullable=False)
    bytes_sent = Column(BigInteger, default=0)
    bytes_received = Column(BigInteger, default=0)
    last_handshake = Column(DateTime, nullable=True)
    session_start = Column(DateTime, default=datetime.utcnow)
    session_end = Column(DateTime, nullable=True)
    
    user = relationship("User", back_populates="usage_logs")
    vpn_config = relationship("VPNConfig", back_populates="usage_logs")

class IPAllocation(Base):
    __tablename__ = "ip_allocations"
    
    id = Column(Integer, primary_key=True, index=True)
    server_id = Column(Integer, ForeignKey("servers.id"), nullable=False)
    ip_address = Column(String, nullable=False)
    is_allocated = Column(Boolean, default=False)
    allocated_to = Column(Integer, ForeignKey("vpn_configs.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)