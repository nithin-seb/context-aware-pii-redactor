"""Entity merger and deduplication service for combining deterministic local detections with Gemini contextual AI results."""

import re
from typing import Any, Dict, List, Optional

RISK_WEIGHTS = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
}

# Type specificity ranking (higher number = more specific classification)
TYPE_SPECIFICITY = {
    "CREDENTIAL": 10,
    "PASSWORD": 10,
    "API_KEY": 10,
    "AADHAAR": 9,
    "PAN": 9,
    "FINANCIAL_ID": 8,
    "MEDICAL": 8,
    "EMAIL": 8,
    "PHONE": 8,
    "PERSON_NAME": 7,
    "ADDRESS": 6,
    "LOCATION": 4,
    "ORGANIZATION": 4,
    "OTHER_PII": 1,
}


def _normalize_value(val: str) -> str:
    """Normalize entity value for robust matching."""
    if not val:
        return ""
    # Strip whitespace, lower-case, remove outer punctuation
    v = val.strip().lower()
    v = re.sub(r"\s+", " ", v)
    v = re.sub(r"^[,\.\:\;\-\'\"]+|[,\.\:\;\-\'\"]+$", "", v)
    return v


def _is_equivalent_or_overlapping(val1: str, val2: str) -> bool:
    """Determine if two entity values refer to the exact same text or overlap significantly."""
    norm1 = _normalize_value(val1)
    norm2 = _normalize_value(val2)

    if not norm1 or not norm2:
        return False

    if norm1 == norm2:
        return True

    # Check alphanumeric stripped equality (e.g. 1234-5678-9012 vs 1234 5678 9012)
    clean1 = re.sub(r"\W", "", norm1)
    clean2 = re.sub(r"\W", "", norm2)
    if clean1 and clean1 == clean2:
        return True

    # Check substring containment if long enough
    if len(clean1) >= 4 and len(clean2) >= 4:
        if clean1 in clean2 or clean2 in clean1:
            return True

    return False


def _choose_best_type(type_a: str, type_b: str) -> str:
    """Select the more specific entity classification."""
    spec_a = TYPE_SPECIFICITY.get(type_a.upper(), 2)
    spec_b = TYPE_SPECIFICITY.get(type_b.upper(), 2)
    return type_a if spec_a >= spec_b else type_b


def _choose_higher_risk(risk_a: str, risk_b: str) -> str:
    """Select the higher risk level between two detections."""
    w_a = RISK_WEIGHTS.get(risk_a.upper(), 1)
    w_b = RISK_WEIGHTS.get(risk_b.upper(), 1)
    return risk_a if w_a >= w_b else risk_b


def merge_entities(
    local_entities: List[Dict[str, Any]],
    gemini_entities: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Merge and deduplicate entities detected locally and via Gemini AI.

    Returns:
        List of deduplicated entity dictionaries with keys:
        - type: str
        - value: str
        - risk: str (LOW, MEDIUM, HIGH, CRITICAL)
        - reason: str
        - recommended_action: str
        - source: 'local' | 'gemini' | 'local+gemini'
    """
    merged: List[Dict[str, Any]] = []
    matched_gemini_indices = set()

    for local in local_entities:
        local_val = str(local.get("value", "")).strip()
        local_type = str(local.get("type", "OTHER_PII")).upper()
        local_risk = str(local.get("risk", "MEDIUM")).upper()
        local_reason = str(local.get("reason", "Deterministic pattern detection."))
        local_action = str(local.get("recommended_action", "Redact or mask sensitive information."))

        # Find matching Gemini entity if any
        matching_gemini = None
        for g_idx, gemini in enumerate(gemini_entities):
            if g_idx in matched_gemini_indices:
                continue
            gemini_val = str(gemini.get("value", "")).strip()
            if _is_equivalent_or_overlapping(local_val, gemini_val):
                matching_gemini = gemini
                matched_gemini_indices.add(g_idx)
                break

        if matching_gemini:
            # Combine information
            gemini_type = str(matching_gemini.get("type", "OTHER_PII")).upper()
            gemini_risk = str(matching_gemini.get("risk", "MEDIUM")).upper()
            gemini_reason = str(matching_gemini.get("reason", "")).strip()
            gemini_action = str(matching_gemini.get("recommended_action", "")).strip()

            best_type = _choose_best_type(local_type, gemini_type)
            best_risk = _choose_higher_risk(local_risk, gemini_risk)
            best_reason = gemini_reason if gemini_reason else local_reason
            best_action = gemini_action if gemini_action else local_action

            merged.append(
                {
                    "type": best_type,
                    "value": local_val,  # Keep the exact extracted string
                    "risk": best_risk,
                    "reason": best_reason,
                    "recommended_action": best_action,
                    "source": "local+gemini",
                }
            )
        else:
            merged.append(
                {
                    "type": local_type,
                    "value": local_val,
                    "risk": local_risk,
                    "reason": local_reason,
                    "recommended_action": local_action,
                    "source": "local",
                }
            )

    # Add remaining unmatched Gemini entities
    for g_idx, gemini in enumerate(gemini_entities):
        if g_idx not in matched_gemini_indices:
            gemini_val = str(gemini.get("value", "")).strip()
            gemini_type = str(gemini.get("type", "OTHER_PII")).upper()
            gemini_risk = str(gemini.get("risk", "MEDIUM")).upper()
            gemini_reason = str(gemini.get("reason", f"{gemini_type.title()} identified in document."))
            gemini_action = str(gemini.get("recommended_action", "Redact or mask sensitive information."))

            # Double check we haven't already included an equivalent value in merged
            already_exists = False
            for existing in merged:
                if _is_equivalent_or_overlapping(existing["value"], gemini_val):
                    already_exists = True
                    # Upgrade source if not already
                    if existing["source"] == "local":
                        existing["source"] = "local+gemini"
                    break

            if not already_exists:
                merged.append(
                    {
                        "type": gemini_type,
                        "value": gemini_val,
                        "risk": gemini_risk,
                        "reason": gemini_reason,
                        "recommended_action": gemini_action,
                        "source": "gemini",
                    }
                )

    return merged
