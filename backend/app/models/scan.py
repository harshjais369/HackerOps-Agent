from sqlalchemy import Column, String, Float, DateTime, Text, Enum
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
from app.database import Base

class Scan(Base):
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    target_url = Column(String(512), nullable=False)
    target_host = Column(String(255), nullable=False)
    resolved_ip = Column(String(128), nullable=True)
    scan_depth = Column(String(32), default="standard")  # quick, standard, deep, compliance
    status = Column(String(32), default="pending")       # pending, running, completed, failed
    risk_score = Column(Float, default=0.0)             # 0 - 100
    compliance_grade = Column(String(4), default="A")    # A+, A, B, C, D, F
    error_message = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    # Relationships
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan", lazy="selectin")
    nodes = relationship("GraphNode", back_populates="scan", cascade="all, delete-orphan", lazy="selectin")
    edges = relationship("GraphEdge", back_populates="scan", cascade="all, delete-orphan", lazy="selectin")
    patches = relationship("Patch", back_populates="scan", cascade="all, delete-orphan", lazy="selectin")
