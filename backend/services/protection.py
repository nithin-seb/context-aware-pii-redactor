"""
Document protection module for PrivacyLens.

Provides three protection modes for sensitive PII in documents:
1. REDACT: Completely replaces sensitive values with category tokens (e.g. [REDACTED: EMAIL])
2. MASK: Partially masks values while preserving structural context (e.g. j***@example.com)
3. ANONYMIZE: Replaces sensitive values with consistent synthetic surrogate tokens (e.g. [PERSON_1])
"""

import re
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from .privacy_score import _extract_field

# Canonical category mapping for anonymization tokens and redact tags
CANONICAL_TYPES: Dict[str, str] = {
    "NAME": "PERSON",
    "PERSON": "PERSON",
    "INDIVIDUAL": "PERSON",
    "FULL_NAME": "PERSON",
    "FIRST_NAME": "PERSON",
    "LAST_NAME": "PERSON",
    "EMAIL": "EMAIL",
    "EMAIL_ADDRESS": "EMAIL",
    "PHONE": "PHONE",
    "PHONE_NUMBER": "PHONE",
    "TELEPHONE": "PHONE",
    "MOBILE": "PHONE",
    "CREDIT_CARD": "CREDIT_CARD",
    "CREDIT_CARD_NUMBER": "CREDIT_CARD",
    "CARD_NUMBER": "CREDIT_CARD",
    "DEBIT_CARD": "CREDIT_CARD",
    "SSN": "SSN",
    "SOCIAL_SECURITY_NUMBER": "SSN",
    "ADDRESS": "ADDRESS",
    "STREET_ADDRESS": "ADDRESS",
    "LOCATION": "ADDRESS",
    "PASSPORT": "PASSPORT",
    "BANK_ACCOUNT": "BANK_ACCOUNT",
    "DATE": "DATE",
    "DOB": "DATE",
    "DATE_OF_BIRTH": "DATE",
    "ORGANIZATION": "ORGANIZATION",
    "COMPANY": "ORGANIZATION",
    "IP_ADDRESS": "IP_ADDRESS",
}


def _get_canonical_type(entity_type: Optional[str]) -> str:
    """Normalizes an entity type to a clean canonical uppercase label."""
    if not entity_type or not isinstance(entity_type, str):
        return "PII"
    cleaned = entity_type.strip().upper().replace(" ", "_").replace("-", "_")
    return CANONICAL_TYPES.get(cleaned, cleaned)


# ==============================================================================
# MASKING STRATEGIES
# ==============================================================================

def _mask_email(text: str) -> str:
    """
    Masks email while preserving initial character and domain:
    john@example.com -> j***@example.com
    j.smith@corp.org -> j***@corp.org
    """
    if "@" not in text:
        return _mask_generic(text)

    parts = text.split("@", 1)
    username, domain = parts[0], parts[1]

    if not username:
        return f"***@{domain}"

    first_char = username[0]
    return f"{first_char}***@{domain}"


def _mask_phone(text: str) -> str:
    """
    Masks phone numbers preserving formatting and the last 4 digits:
    9876543210 -> ******3210
    (555) 123-4567 -> (***) ***-4567
    """
    digits = [c for c in text if c.isdigit()]
    if len(digits) <= 4:
        # If 4 or fewer digits, mask all except the very last digit
        kept = 1 if len(digits) > 1 else 0
    else:
        kept = 4

    digits_to_mask = len(digits) - kept
    masked_digit_count = 0
    result_chars = []

    for char in text:
        if char.isdigit():
            if masked_digit_count < digits_to_mask:
                result_chars.append("*")
                masked_digit_count += 1
            else:
                result_chars.append(char)
        else:
            result_chars.append(char)

    return "".join(result_chars)


def _mask_credit_card(text: str) -> str:
    """
    Masks credit card numbers preserving formatting and the last 4 digits:
    1234-5678-9012-3456 -> ****-****-****-3456
    1234567890123456 -> ************3456
    """
    return _mask_phone(text)


def _mask_ssn(text: str) -> str:
    """
    Masks SSN preserving the last 4 digits:
    123-45-6789 -> ***-**-6789
    123456789   -> *****6789
    """
    return _mask_phone(text)


def _mask_name(text: str) -> str:
    """
    Masks names by retaining initial letter per word:
    John Smith -> J*** S***
    Alice -> A***
    """
    words = text.split()
    if not words:
        return "***"

    masked_words = []
    for word in words:
        if len(word) == 0:
            continue
        first_letter = word[0]
        masked_words.append(f"{first_letter}***")

    return " ".join(masked_words)


def _mask_address(text: str) -> str:
    """
    Masks address street numbers and details:
    123 Main St -> *** Main St
    """
    # Replace leading street numbers with ***
    masked = re.sub(r"^\d+", "***", text.strip())
    if masked == text.strip():
        # Mask internal digit clusters
        masked = re.sub(r"\d+", "***", masked)
    return masked


def _mask_generic(text: str) -> str:
    """
    Safe generic masking fallback for arbitrary entity types:
    Keeps first and optionally last character with asterisks in between.
    """
    stripped = text.strip()
    length = len(stripped)

    if length <= 2:
        return "*" * max(1, length)
    elif length <= 4:
        return stripped[0] + "***"
    else:
        return stripped[0] + "***" + stripped[-1]


def get_masked_value(text: str, entity_type: Optional[str]) -> str:
    """Routes entity text to appropriate masking handler based on entity type."""
    canonical = _get_canonical_type(entity_type)

    if canonical == "EMAIL":
        return _mask_email(text)
    elif canonical in ("PHONE", "MOBILE"):
        return _mask_phone(text)
    elif canonical == "CREDIT_CARD":
        return _mask_credit_card(text)
    elif canonical == "SSN":
        return _mask_ssn(text)
    elif canonical == "PERSON":
        return _mask_name(text)
    elif canonical == "ADDRESS":
        return _mask_address(text)
    else:
        return _mask_generic(text)


# ==============================================================================
# SPAN PREPARATION & RESOLUTION
# ==============================================================================

def _extract_and_resolve_spans(
    original_text: str,
    entities: List[Any],
) -> List[Dict[str, Any]]:
    """
    Prepares, validates, and de-duplicates entity spans.
    Resolves overlaps gracefully by prioritizing larger or earlier spans.
    """
    doc_len = len(original_text)
    candidate_spans: List[Dict[str, Any]] = []

    for entity in entities:
        text_val = _extract_field(entity, "text", "value", "content", "raw")
        raw_type = _extract_field(entity, "entity_type", "type", "label", "category") or "PII"
        start_val = _extract_field(entity, "start", "start_char", "start_offset", "start_idx")
        end_val = _extract_field(entity, "end", "end_char", "end_offset", "end_idx")

        if text_val is None and (start_val is None or end_val is None):
            continue

        # Convert offsets if present
        start_int: Optional[int] = None
        end_int: Optional[int] = None
        try:
            if start_val is not None:
                start_int = int(start_val)
            if end_val is not None:
                end_int = int(end_val)
        except (ValueError, TypeError):
            start_int = None
            end_int = None

        # If offsets are missing or invalid, search for text occurrence in document
        if start_int is None or end_int is None or start_int < 0 or end_int > doc_len or start_int >= end_int:
            if text_val and isinstance(text_val, str) and text_val in original_text:
                # Find all occurrences of text_val in document
                search_idx = 0
                while search_idx < doc_len:
                    found_idx = original_text.find(text_val, search_idx)
                    if found_idx == -1:
                        break
                    candidate_spans.append({
                        "start": found_idx,
                        "end": found_idx + len(text_val),
                        "text": text_val,
                        "entity_type": raw_type,
                        "original_entity": entity,
                    })
                    search_idx = found_idx + len(text_val)
            continue

        # Validate that the slice matches or extract from text
        span_text = original_text[start_int:end_int]
        extracted_text = str(text_val) if text_val is not None else span_text

        candidate_spans.append({
            "start": start_int,
            "end": end_int,
            "text": extracted_text,
            "entity_type": raw_type,
            "original_entity": entity,
        })

    if not candidate_spans:
        return []

    # Sort candidates by:
    # 1. start offset ascending
    # 2. span length descending (prioritize longer matching span in overlaps)
    sorted_candidates = sorted(
        candidate_spans,
        key=lambda s: (s["start"], -(s["end"] - s["start"])),
    )

    # Filter non-overlapping spans
    resolved: List[Dict[str, Any]] = []
    last_end = -1

    for span in sorted_candidates:
        if span["start"] >= last_end:
            resolved.append(span)
            last_end = span["end"]

    return resolved


# ==============================================================================
# MAIN PROTECTION ENGINES
# ==============================================================================

class DocumentProtector:
    """
    Manages document protection state and executes safe replacements.
    Maintains anonymization mappings consistently across occurrences.
    """

    def __init__(self) -> None:
        self.type_counters: Dict[str, int] = {}
        self.anonymize_mapping: Dict[Tuple[str, str], str] = {}

    def get_anonymized_placeholder(self, text: str, entity_type: str) -> str:
        """
        Returns a consistent anonymized placeholder for a given entity value and type.
        Same sensitive value always receives the identical placeholder during one operation.
        """
        canonical = _get_canonical_type(entity_type)
        lookup_key = (canonical, text.strip().lower())

        if lookup_key in self.anonymize_mapping:
            return self.anonymize_mapping[lookup_key]

        current_count = self.type_counters.get(canonical, 0) + 1
        self.type_counters[canonical] = current_count

        placeholder = f"[{canonical}_{current_count}]"
        self.anonymize_mapping[lookup_key] = placeholder
        return placeholder

    def protect(
        self,
        original_text: str,
        entities: Optional[List[Any]] = None,
        mode: Union[str, Any] = "redact",
    ) -> Dict[str, Any]:
        """
        Protects document text using the specified mode:
        'redact', 'mask', or 'anonymize'.
        """
        if not original_text:
            return {
                "protected_text": "",
                "mode": str(mode).lower(),
                "entities_protected": 0,
                "anonymization_mapping": {},
            }

        if not entities:
            return {
                "protected_text": original_text,
                "mode": str(mode).lower(),
                "entities_protected": 0,
                "anonymization_mapping": {},
            }

        mode_str = str(mode).strip().lower()
        if hasattr(mode, "value"):
            mode_str = str(mode.value).strip().lower()

        # Step 1: Extract, validate, and resolve non-overlapping spans
        resolved_spans = _extract_and_resolve_spans(original_text, entities)
        if not resolved_spans:
            return {
                "protected_text": original_text,
                "mode": mode_str,
                "entities_protected": 0,
                "anonymization_mapping": {},
            }

        # Step 2: Determine replacements for each span (in document order)
        replacement_actions: List[Dict[str, Any]] = []
        for span in resolved_spans:
            entity_text = span["text"]
            entity_type = span["entity_type"]

            if mode_str == "mask":
                replacement = get_masked_value(entity_text, entity_type)
            elif mode_str == "anonymize":
                replacement = self.get_anonymized_placeholder(entity_text, entity_type)
            else:
                # Default: REDACT
                canonical = _get_canonical_type(entity_type)
                if canonical == "PII":
                    replacement = "[REDACTED]"
                else:
                    replacement = f"[REDACTED: {canonical}]"

            replacement_actions.append({
                "start": span["start"],
                "end": span["end"],
                "replacement": replacement,
            })

        # Step 3: Perform safe replacement from end to beginning
        # Sorting by start DESCENDING guarantees offsets for preceding text remain valid!
        protected_text = original_text
        for action in sorted(replacement_actions, key=lambda a: a["start"], reverse=True):
            start = action["start"]
            end = action["end"]
            rep = action["replacement"]
            protected_text = protected_text[:start] + rep + protected_text[end:]

        # Friendly mapping format: "John Smith" -> "[PERSON_1]"
        exportable_mapping = {
            k[1]: v for k, v in self.anonymize_mapping.items()
        }

        return {
            "protected_text": protected_text,
            "mode": mode_str,
            "entities_protected": len(resolved_spans),
            "anonymization_mapping": exportable_mapping,
        }


# ==============================================================================
# CONVENIENCE STANDALONE FUNCTIONS FOR PERSON 1
# ==============================================================================

def protect_document(
    original_text: str,
    entities: Optional[List[Any]] = None,
    mode: str = "redact",
) -> str:
    """
    Main protection interface.

    Args:
        original_text: The complete original document string.
        entities: List of detected entity dictionaries or objects.
        mode: Protection mode ('redact', 'mask', or 'anonymize').

    Returns:
        The protected document string with sensitive data transformed.
    """
    protector = DocumentProtector()
    result = protector.protect(original_text, entities, mode=mode)
    return result["protected_text"]


def redact_text(
    original_text: str,
    entities: Optional[List[Any]] = None,
) -> str:
    """Convenience wrapper for REDACT mode."""
    return protect_document(original_text, entities, mode="redact")


def mask_text(
    original_text: str,
    entities: Optional[List[Any]] = None,
) -> str:
    """Convenience wrapper for MASK mode."""
    return protect_document(original_text, entities, mode="mask")


def anonymize_text(
    original_text: str,
    entities: Optional[List[Any]] = None,
) -> str:
    """Convenience wrapper for ANONYMIZE mode."""
    return protect_document(original_text, entities, mode="anonymize")
