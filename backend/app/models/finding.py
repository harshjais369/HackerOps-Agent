from sqlalchemy import Column, String, Float, DateTime, Text, ForeignKey, JSON
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
from app.database import Base

class Finding(Base):
    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(16), nullable=False) # CRITICAL, HIGH, MEDIUM, LOW, INFO
    cvss_score = Column(Float, nullable=False)    # 0.0 - 10.0
    owasp_category = Column(String(64), nullable=True) # e.g. A05:2021-Security Misconfiguration
    pci_dss_ref = Column(String(64), nullable=True)    # e.g. PCI-DSS v4.0 Req 6.4.3
    category = Column(String(64), nullable=False)      # headers, tls, cors, paths, ports, dns
    evidence = Column(Text, nullable=True)
    remediation_hint = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    scan = relationship("Scan", back_populates="findings")
    patch = relationship("Patch", back_populates="finding", uselist=False, cascade="all, delete-orphan")
