from sqlalchemy import Column, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
from app.database import Base

class Patch(Base):
    __tablename__ = "patches"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    finding_id = Column(String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=True)

    patch_type = Column(String(32), nullable=False) # nginx, express, fastapi, dns, env, docker
    title = Column(String(255), nullable=False)
    file_target = Column(String(255), nullable=False)
    diff_content = Column(Text, nullable=False)
    explanation = Column(Text, nullable=False)

    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="patches")
    finding = relationship("Finding", back_populates="patch")
