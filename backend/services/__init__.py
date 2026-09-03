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
from .document_parser import extract_document
from .local_detector import detect_local_pii
from .gemini import detect_gemini_pii
from .entity_merger import merge_entities

__all__ = [
    "calculate_privacy_score",
    "get_risk_level",
    "generate_score_breakdown",
    "SEVERITY_WEIGHTS",
    "protect_document",
    "redact_text",
    "mask_text",
    "anonymize_text",
    "extract_document",
    "detect_local_pii",
    "detect_gemini_pii",
    "merge_entities",
]
