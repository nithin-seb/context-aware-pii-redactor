"""
Data schemas and contracts for PrivacyLens.

These models define standard structures for detected PII entities,
privacy risk evaluation results, and document protection requests/responses.
Compatible with FastAPI request/response validation.
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ProtectionMode(str, Enum):
    REDACT = "redact"
    MASK = "mask"
    ANONYMIZE = "anonymize"


class DetectedEntity(BaseModel):
    """
    Schema representing a detected PII entity in a document.
    Permissive to accommodate variations from different detection engines.
    """
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    text: str = Field(..., description="The raw sensitive text extracted from the document")
    entity_type: str = Field(..., alias="type", description="Entity category, e.g. EMAIL, PHONE, SSN, NAME")
    start: Optional[int] = Field(None, alias="start_char", description="Starting character index")
    end: Optional[int] = Field(None, alias="end_char", description="Ending character index")
    confidence: Optional[float] = Field(1.0, description="Detection confidence score (0.0 - 1.0)")
    severity: Optional[str] = Field(None, alias="sensitivity", description="Severity or sensitivity rating")


class PrivacyScoreBreakdown(BaseModel):
    """Detailed breakdown of privacy risk calculation."""
    raw_score: float = Field(..., description="Raw cumulative points before normalization")
    capped_score: int = Field(..., description="Normalized score bounded between 0 and 100")
    points_by_severity: Dict[str, float] = Field(default_factory=dict)
    entity_breakdown: List[Dict[str, Any]] = Field(default_factory=list)


class PrivacyScoreResult(BaseModel):
    """Result returned by the privacy scoring module."""
    score: int = Field(..., ge=0, le=100, description="Normalized privacy risk score (0-100)")
    risk_level: str = Field(..., description="Risk category: LOW (0-20), MEDIUM (21-50), HIGH (51-75), CRITICAL (76-100)")
    total_entities: int = Field(..., description="Total count of detected PII entities")
    severity_counts: Dict[str, int] = Field(
        default_factory=lambda: {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    )
    score_breakdown: PrivacyScoreBreakdown


class ProtectionRequest(BaseModel):
    """Request payload for document protection."""
    text: str = Field(..., description="Original document text to protect")
    entities: List[DetectedEntity] = Field(default_factory=list, description="Detected entities in the document")
    mode: ProtectionMode = Field(default=ProtectionMode.REDACT, description="Protection mode: redact, mask, or anonymize")


class ProtectionResponse(BaseModel):
    """Response payload containing protected document text."""
    original_length: int
    protected_length: int
    mode: str
    protected_text: str
    entities_protected: int
    anonymization_mapping: Optional[Dict[str, str]] = None
