from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional, Dict, Any
from datetime import datetime

class FindingBase(BaseModel):
    title: str
    description: str
    severity: str # CRITICAL, HIGH, MEDIUM, LOW, INFO
    cvss_score: float = Field(ge=0.0, le=10.0)
    owasp_category: Optional[str] = None
    pci_dss_ref: Optional[str] = None
    category: str
    evidence: Optional[str] = None
    remediation_hint: Optional[str] = None

class FindingOut(FindingBase):
    model_config = ConfigDict(from_attributes=True)
    id: str
    scan_id: str
    created_at: datetime

class PatchOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    scan_id: str
    finding_id: Optional[str] = None
    patch_type: str
    title: str
    file_target: str
    diff_content: str
    explanation: str
    created_at: datetime

class GraphNodeOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    scan_id: str
    node_type: str
    label: str
    severity: Optional[str] = None
    node_metadata: Optional[Dict[str, Any]] = None

class GraphEdgeOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    scan_id: str
    source_id: str
    target_id: str
    label: Optional[str] = None
    animated: bool = True

class ScanCreate(BaseModel):
    target: str = Field(..., description="Target URL or hostname to assess")
    scan_depth: str = Field(default="standard", description="Scan depth: quick, standard, deep, compliance")

class ScanSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    target_url: str
    target_host: str
    resolved_ip: Optional[str] = None
    scan_depth: str
    status: str
    risk_score: float
    compliance_grade: str
    created_at: datetime
    completed_at: Optional[datetime] = None

class ScanDetail(ScanSummary):
    model_config = ConfigDict(from_attributes=True)
    error_message: Optional[str] = None
    findings: List[FindingOut] = []
    nodes: List[GraphNodeOut] = []
    edges: List[GraphEdgeOut] = []
    patches: List[PatchOut] = []

class WebSocketMessage(BaseModel):
    type: str # log, node, edge, finding, patch, status, complete, error
    payload: Dict[str, Any]
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())

