from pydantic import BaseModel, Field
from typing import List, Dict, Optional
from datetime import datetime

class AssetPayload(BaseModel):
    asset_id: str
    asset_type: str
    value: str
    open_ports: List[int]
    source: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class RawFinding(BaseModel):
    cve_id: str
    cvss_base: float
    vulnerability_name: str
    tool: str

class EnrichedFinding(BaseModel):
    asset_id: str
    vulnerability: str
    cve_id: str
    tool_used: str
    composite_risk_score: float
    sla_tier: str
    metrics: Dict[str, float]
    timestamp: datetime = Field(default_factory=datetime.utcnow)
