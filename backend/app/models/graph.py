from sqlalchemy import Column, String, Boolean, ForeignKey, JSON
from sqlalchemy.orm import relationship
from app.database import Base

class GraphNode(Base):
    __tablename__ = "graph_nodes"

    id = Column(String(64), primary_key=True)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    
    node_type = Column(String(32), nullable=False) # target, port, service, vulnerability, impact, patch
    label = Column(String(255), nullable=False)
    severity = Column(String(16), nullable=True)   # CRITICAL, HIGH, MEDIUM, LOW, INFO
    node_metadata = Column(JSON, default=dict)

    scan = relationship("Scan", back_populates="nodes")


class GraphEdge(Base):
    __tablename__ = "graph_edges"

    id = Column(String(64), primary_key=True)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    
    source_id = Column(String(64), nullable=False)
    target_id = Column(String(64), nullable=False)
    label = Column(String(128), nullable=True)
    animated = Column(Boolean, default=True)

    scan = relationship("Scan", back_populates="edges")
