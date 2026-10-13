"""
Pydantic Data Schemas and Validation Models for Deception Ops.
Defines payloads for incoming triggers, threat enrichment, containment actions, and alerts.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


class TokenType(str, Enum):
    AWS_HONEY_KEY = "aws_honey_key"
    KUBECONFIG = "kubeconfig"
    CANARY_PDF = "canary_pdf"
    DATABASE_ENV = "database_env"
    WEBHOOK_TOKEN = "webhook_token"
    GENERIC = "generic"


class NetworkContext(str, Enum):
    INTERNAL_LATERAL_MOVEMENT = "INTERNAL_LATERAL_MOVEMENT"
    CORPORATE_VPN = "CORPORATE_VPN"
    TOR_EXIT_NODE = "TOR_EXIT_NODE"
    EXTERNAL_INTERNET_ACCESS = "EXTERNAL_INTERNET_ACCESS"
    LOOPBACK_LOCAL_SIMULATION = "LOOPBACK_LOCAL_SIMULATION"
    SUSPICIOUS_DATACENTER_PROXY = "SUSPICIOUS_DATACENTER_PROXY"


class CanaryTrigger(BaseModel):
    """Normalized payload representing an adversary triggering a canary tripwire."""
    token_id: str = Field(..., description="Unique canary identifier")
    token_type: str = Field(default="generic", description="Type of decoy triggered")
    source_ip: str = Field(..., description="Observed source IPv4/IPv6 address")
    user_agent: str = Field(default="unknown", description="Client User-Agent header")
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 UTC timestamp of trigger event",
    )
    headers: Dict[str, str] = Field(default_factory=dict, description="Sanitized HTTP headers")
    query_params: Dict[str, str] = Field(default_factory=dict, description="URL query parameters")
    payload: Dict[str, Any] = Field(default_factory=dict, description="Raw request body or parameters")

    @field_validator("source_ip")
    @classmethod
    def sanitize_ip(cls, v: str) -> str:
        # Strip potential port or whitespace
        cleaned = v.strip().split(":")[0] if ":" in v and not v.startswith(":") and "." in v else v.strip()
        return cleaned or "127.0.0.1"


class EnrichmentData(BaseModel):
    """Enriched network, ASN, and geolocation intelligence for the source IP."""
    source_ip: str
    is_private_ip: bool = False
    is_corporate_vpn: bool = False
    is_tor_exit_node: bool = False
    is_datacenter_proxy: bool = False
    country_code: Optional[str] = "XX"
    country_name: Optional[str] = "Unknown"
    city: Optional[str] = "Unknown"
    asn: Optional[int] = None
    asn_org: Optional[str] = "Unknown ASN"
    network_context: NetworkContext = NetworkContext.EXTERNAL_INTERNET_ACCESS
    confidence_score: float = 1.0  # 1.0 = 100% true positive


class ContainmentAction(BaseModel):
    """Records an automated containment or remediation action."""
    action_type: str
    target: str
    status: str
    executed_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    details: Dict[str, Any] = Field(default_factory=dict)


class CanaryAlert(BaseModel):
    """High-fidelity security incident alert emitted to SIEM and dispatchers."""
    alert_id: str = Field(..., description="UUID identifier for the alert")
    event: str = Field(default="CRITICAL_CANARY_TRIPWIRE_TRIGGERED")
    severity: str = Field(default="CRITICAL")
    fidelity: str = Field(default="100%", description="Always 100% since decoy has no business use")
    ttp: str = Field(..., description="Associated MITRE ATT&CK techniques")
    timestamp: str
    token_id: str
    token_type: str
    source_ip: str
    user_agent: str
    network_context: str
    enrichment: EnrichmentData
    action_required: str = Field(default="IMMEDIATE_HOST_CONTAINMENT")
    containment_actions: List[ContainmentAction] = Field(default_factory=list)
    raw_metadata: Dict[str, Any] = Field(default_factory=dict)


class AlertsListResponse(BaseModel):
    """Standardized response schema for querying alerts."""
    alerts: List[CanaryAlert]
    total: int
    filter_applied: Optional[Dict[str, Any]] = None
