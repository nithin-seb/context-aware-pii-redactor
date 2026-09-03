"""
PrivacyLens services package.
"""

from .privacy_score import (
    calculate_privacy_score,
    get_risk_level,
    generate_score_breakdown,
    SEVERITY_WEIGHTS,
)
from .protection import (
    protect_document,
    redact_text,
    mask_text,
    anonymize_text,
)

__all__ = [
    "calculate_privacy_score",
    "get_risk_level",
    "generate_score_breakdown",
    "SEVERITY_WEIGHTS",
    "protect_document",
    "redact_text",
    "mask_text",
    "anonymize_text",
]
