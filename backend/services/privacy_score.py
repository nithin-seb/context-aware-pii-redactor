"""
Privacy scoring engine for PrivacyLens.

Evaluates detected PII entities and computes normalized privacy risk scores
(0-100) and associated risk levels (LOW, MEDIUM, HIGH, CRITICAL).
"""

from typing import Any, Dict, List, Optional, Union

# Standard severity weights specified in PrivacyLens project requirements
SEVERITY_WEIGHTS: Dict[str, int] = {
    "CRITICAL": 30,
    "HIGH": 20,
    "MEDIUM": 10,
    "LOW": 5,
}

# Heuristic default severities by entity category if not explicitly provided
DEFAULT_ENTITY_SEVERITY: Dict[str, str] = {
    "SSN": "CRITICAL",
    "SOCIAL_SECURITY_NUMBER": "CRITICAL",
    "CREDIT_CARD": "CRITICAL",
    "CREDIT_CARD_NUMBER": "CRITICAL",
    "BANK_ACCOUNT": "CRITICAL",
    "PASSPORT": "CRITICAL",
    "PASSWORD": "CRITICAL",
    "SECRET_KEY": "CRITICAL",
    "AADHAAR": "CRITICAL",
    "PAN": "CRITICAL",
    "CREDENTIAL": "CRITICAL",
    "API_KEY": "CRITICAL",
    "FINANCIAL_ID": "HIGH",
    "PHONE": "HIGH",
    "PHONE_NUMBER": "HIGH",
    "EMAIL": "HIGH",
    "EMAIL_ADDRESS": "HIGH",
    "MEDICAL_RECORD": "HIGH",
    "MEDICAL": "HIGH",
    "HEALTH_INFO": "HIGH",
    "FINANCIAL_INFO": "HIGH",
    "BIOMETRIC": "HIGH",
    "NAME": "MEDIUM",
    "PERSON": "MEDIUM",
    "PERSON_NAME": "MEDIUM",
    "ADDRESS": "MEDIUM",
    "LOCATION": "MEDIUM",
    "DATE_OF_BIRTH": "MEDIUM",
    "DOB": "MEDIUM",
    "ORGANIZATION": "LOW",
    "COMPANY": "LOW",
    "IP_ADDRESS": "LOW",
    "URL": "LOW",
    "MISC": "LOW",
    "OTHER_PII": "LOW",
}


def _extract_field(entity: Any, *keys: str, default: Any = None) -> Any:
    """
    Extracts a field from either a dictionary or an object attribute,
    checking multiple possible naming variations.
    """
    if entity is None:
        return default

    # Check dict keys
    if isinstance(entity, dict):
        for key in keys:
            if key in entity and entity[key] is not None:
                return entity[key]
        return default

    # Check object attributes
    for key in keys:
        if hasattr(entity, key):
            val = getattr(entity, key)
            if val is not None:
                return val

    # Pydantic or custom __getitem__ fallback
    if hasattr(entity, "__getitem__"):
        for key in keys:
            try:
                val = entity[key]
                if val is not None:
                    return val
            except (KeyError, TypeError, IndexError):
                pass

    return default


def normalize_severity(severity_input: Optional[str], entity_type: Optional[str] = None) -> str:
    """
    Normalizes severity/sensitivity input string to one of:
    CRITICAL, HIGH, MEDIUM, LOW.
    Falls back to entity type heuristic or MEDIUM if unspecified.
    """
    if severity_input and isinstance(severity_input, str):
        normalized = severity_input.strip().upper()
        if normalized in SEVERITY_WEIGHTS:
            return normalized

    # Fallback to entity type lookup
    if entity_type and isinstance(entity_type, str):
        lookup_type = entity_type.strip().upper()
        if lookup_type in DEFAULT_ENTITY_SEVERITY:
            return DEFAULT_ENTITY_SEVERITY[lookup_type]

    return "MEDIUM"


def get_risk_level(score: Union[int, float]) -> str:
    """
    Classifies a privacy risk score (0-100) into risk levels:
    - 0-20   -> LOW
    - 21-50  -> MEDIUM
    - 51-75  -> HIGH
    - 76-100 -> CRITICAL
    """
    rounded = round(score)
    if rounded <= 20:
        return "LOW"
    elif rounded <= 50:
        return "MEDIUM"
    elif rounded <= 75:
        return "HIGH"
    else:
        return "CRITICAL"


def generate_score_breakdown(
    entities: Optional[List[Any]] = None,
    use_confidence: bool = False,
) -> Dict[str, Any]:
    """
    Generates an itemized breakdown of privacy risk calculation,
    including severity counts, points per severity category, and per-entity details.
    """
    if not entities:
        return {
            "raw_score": 0.0,
            "capped_score": 0,
            "points_by_severity": {k: 0.0 for k in SEVERITY_WEIGHTS},
            "severity_counts": {k: 0 for k in SEVERITY_WEIGHTS},
            "entity_breakdown": [],
        }

    severity_counts = {k: 0 for k in SEVERITY_WEIGHTS}
    points_by_severity = {k: 0.0 for k in SEVERITY_WEIGHTS}
    entity_breakdown: List[Dict[str, Any]] = []
    total_raw = 0.0

    for idx, entity in enumerate(entities):
        raw_sev = _extract_field(entity, "severity", "sensitivity", "level", "risk")
        entity_type = _extract_field(entity, "entity_type", "type", "label", "category") or "UNKNOWN"
        entity_text = _extract_field(entity, "text", "value", "content", "raw") or ""
        confidence = _extract_field(entity, "confidence", "score", "confidence_score")

        sev = normalize_severity(raw_sev, entity_type)
        severity_counts[sev] += 1
        base_weight = SEVERITY_WEIGHTS[sev]

        # Calculate entity contribution
        if use_confidence and confidence is not None:
            try:
                conf_val = float(confidence)
                conf_val = max(0.0, min(1.0, conf_val))
                entity_points = base_weight * conf_val
            except (ValueError, TypeError):
                entity_points = float(base_weight)
        else:
            entity_points = float(base_weight)

        points_by_severity[sev] += entity_points
        total_raw += entity_points

        entity_breakdown.append({
            "index": idx,
            "entity_type": entity_type,
            "text_snippet": (entity_text[:20] + "...") if len(entity_text) > 20 else entity_text,
            "severity": sev,
            "base_weight": base_weight,
            "points": round(entity_points, 2),
        })

    capped = min(100, max(0, int(round(total_raw))))

    return {
        "raw_score": round(total_raw, 2),
        "capped_score": capped,
        "points_by_severity": {k: round(v, 2) for k, v in points_by_severity.items()},
        "severity_counts": severity_counts,
        "entity_breakdown": entity_breakdown,
    }


def calculate_privacy_score(
    entities: Optional[List[Any]] = None,
    use_confidence: bool = False,
    document_text: Optional[str] = None,
    gemini_summary: Optional[str] = None,
    gemini_risk_level: Optional[str] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """
    Evaluates detected PII entities and returns a complete privacy scoring result.

    Args:
        entities: List of detected entity objects or dictionaries.
        use_confidence: If True, scales each entity's severity weight by its detection confidence.
        document_text: Optional raw extracted document text.
        gemini_summary: Optional summary generated by Gemini.
        gemini_risk_level: Optional risk level assessed by Gemini.

    Returns:
        Dictionary containing:
        - score: int (0 to 100)
        - risk_score: int (alias for score)
        - risk_level: str ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        - total_entities: int
        - total_detected_entities: int (alias)
        - severity_counts: Dict[str, int]
        - score_breakdown: Dict[str, Any]
        - summary: str
    """
    if not entities:
        return {
            "score": 0,
            "risk_score": 0,
            "risk_level": "LOW",
            "total_entities": 0,
            "total_detected_entities": 0,
            "severity_counts": {k: 0 for k in SEVERITY_WEIGHTS},
            "score_breakdown": {
                "raw_score": 0.0,
                "capped_score": 0,
                "points_by_severity": {k: 0.0 for k in SEVERITY_WEIGHTS},
                "entity_breakdown": [],
            },
            "summary": "No personal identifiable information or sensitive credentials detected.",
        }

    breakdown = generate_score_breakdown(entities, use_confidence=use_confidence)
    score = breakdown["capped_score"]
    risk = get_risk_level(score)

    # If Gemini assessed a higher risk level, allow upgrade
    risk_levels_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    final_risk_level = risk
    if gemini_risk_level and gemini_risk_level in risk_levels_order:
        if risk_levels_order.index(gemini_risk_level) > risk_levels_order.index(risk):
            final_risk_level = gemini_risk_level

    # Formulate summary
    if gemini_summary and "unavailable" not in gemini_summary.lower() and "error" not in gemini_summary.lower():
        summary = gemini_summary
    else:
        types_found = list({
            _extract_field(e, "type", "entity_type", default="PII") for e in entities
        })
        summary = (
            f"Detected {len(entities)} sensitive entities across {len(types_found)} categories "
            f"({', '.join(types_found[:4])}). Document assessed with {final_risk_level} privacy exposure."
        )

    return {
        "score": score,
        "risk_score": score,
        "risk_level": final_risk_level,
        "total_entities": len(entities),
        "total_detected_entities": len(entities),
        "severity_counts": breakdown["severity_counts"],
        "score_breakdown": breakdown,
        "summary": summary,
    }
