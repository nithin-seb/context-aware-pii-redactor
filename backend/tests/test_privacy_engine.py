"""
Unit and integration tests for Person 2 PrivacyLens modules:
- Privacy Risk Scoring (privacy_score.py)
- Document Protection & Redaction/Masking/Anonymization (protection.py)
"""

import pytest
from pydantic import BaseModel

from backend.schemas import DetectedEntity
from backend.services.privacy_score import (
    SEVERITY_WEIGHTS,
    calculate_privacy_score,
    generate_score_breakdown,
    get_risk_level,
    normalize_severity,
)
from backend.services.protection import (
    DocumentProtector,
    anonymize_text,
    mask_text,
    protect_document,
    redact_text,
)


# Simple custom class to verify object attribute compatibility
class CustomEntityObj:
    def __init__(self, text, entity_type, start=None, end=None, severity=None, confidence=1.0):
        self.text = text
        self.entity_type = entity_type
        self.start = start
        self.end = end
        self.severity = severity
        self.confidence = confidence


# ==============================================================================
# PART 1: PRIVACY SCORING TESTS
# ==============================================================================

class TestPrivacyScoreWeights:
    """Verifies standard severity weights: CRITICAL=30, HIGH=20, MEDIUM=10, LOW=5."""

    def test_severity_weight_constants(self):
        assert SEVERITY_WEIGHTS["CRITICAL"] == 30
        assert SEVERITY_WEIGHTS["HIGH"] == 20
        assert SEVERITY_WEIGHTS["MEDIUM"] == 10
        assert SEVERITY_WEIGHTS["LOW"] == 5

    def test_critical_weight_calculation(self):
        entities = [{"entity_type": "SSN", "severity": "CRITICAL"}]
        result = calculate_privacy_score(entities)
        assert result["score"] == 30
        assert result["score_breakdown"]["raw_score"] == 30.0
        assert result["severity_counts"]["CRITICAL"] == 1

    def test_high_weight_calculation(self):
        entities = [{"entity_type": "PHONE", "severity": "HIGH"}]
        result = calculate_privacy_score(entities)
        assert result["score"] == 20
        assert result["score_breakdown"]["raw_score"] == 20.0
        assert result["severity_counts"]["HIGH"] == 1

    def test_medium_weight_calculation(self):
        entities = [{"entity_type": "NAME", "severity": "MEDIUM"}]
        result = calculate_privacy_score(entities)
        assert result["score"] == 10
        assert result["score_breakdown"]["raw_score"] == 10.0
        assert result["severity_counts"]["MEDIUM"] == 1

    def test_low_weight_calculation(self):
        entities = [{"entity_type": "URL", "severity": "LOW"}]
        result = calculate_privacy_score(entities)
        assert result["score"] == 5
        assert result["score_breakdown"]["raw_score"] == 5.0
        assert result["severity_counts"]["LOW"] == 1

    def test_normalization_capping_at_100(self):
        # 4 CRITICAL entities = 4 * 30 = 120, capped to 100
        entities = [{"entity_type": "SSN", "severity": "CRITICAL"} for _ in range(4)]
        result = calculate_privacy_score(entities)
        assert result["score"] == 100
        assert result["score_breakdown"]["raw_score"] == 120.0
        assert result["risk_level"] == "CRITICAL"


class TestPrivacyRiskLevelClassification:
    """
    Verifies classification rules:
    - 0–20   -> LOW
    - 21–50  -> MEDIUM
    - 51–75  -> HIGH
    - 76–100 -> CRITICAL
    """

    def test_low_classification(self):
        assert get_risk_level(0) == "LOW"
        assert get_risk_level(10) == "LOW"
        assert get_risk_level(20) == "LOW"

        # 1 HIGH entity (weight 20) -> score 20 -> LOW
        result = calculate_privacy_score([{"entity_type": "PHONE", "severity": "HIGH"}])
        assert result["score"] == 20
        assert result["risk_level"] == "LOW"

    def test_medium_classification(self):
        assert get_risk_level(21) == "MEDIUM"
        assert get_risk_level(35) == "MEDIUM"
        assert get_risk_level(50) == "MEDIUM"

        # 1 CRITICAL entity (weight 30) -> score 30 -> MEDIUM
        result = calculate_privacy_score([{"entity_type": "SSN", "severity": "CRITICAL"}])
        assert result["score"] == 30
        assert result["risk_level"] == "MEDIUM"

    def test_high_classification(self):
        assert get_risk_level(51) == "HIGH"
        assert get_risk_level(65) == "HIGH"
        assert get_risk_level(75) == "HIGH"

        # 2 CRITICAL (60) -> score 60 -> HIGH
        entities = [
            {"entity_type": "SSN", "severity": "CRITICAL"},
            {"entity_type": "PASSPORT", "severity": "CRITICAL"},
        ]
        result = calculate_privacy_score(entities)
        assert result["score"] == 60
        assert result["risk_level"] == "HIGH"

    def test_critical_classification(self):
        assert get_risk_level(76) == "CRITICAL"
        assert get_risk_level(90) == "CRITICAL"
        assert get_risk_level(100) == "CRITICAL"

        # 3 CRITICAL (90) -> score 90 -> CRITICAL
        entities = [
            {"entity_type": "SSN", "severity": "CRITICAL"},
            {"entity_type": "CREDIT_CARD", "severity": "CRITICAL"},
            {"entity_type": "BANK_ACCOUNT", "severity": "CRITICAL"},
        ]
        result = calculate_privacy_score(entities)
        assert result["score"] == 90
        assert result["risk_level"] == "CRITICAL"

    def test_empty_entity_list(self):
        result = calculate_privacy_score([])
        assert result["score"] == 0
        assert result["risk_level"] == "LOW"
        assert result["total_entities"] == 0
        assert result["severity_counts"] == {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    def test_none_entity_list(self):
        result = calculate_privacy_score(None)
        assert result["score"] == 0
        assert result["risk_level"] == "LOW"


class TestScoringInputFlexibility:
    """Verifies tolerance for sensitivity/severity naming and object vs dict."""

    def test_sensitivity_alias(self):
        entity = {"entity_type": "EMAIL", "sensitivity": "HIGH"}
        result = calculate_privacy_score([entity])
        assert result["score"] == 20
        assert result["severity_counts"]["HIGH"] == 1

    def test_lowercase_severity(self):
        entity = {"type": "SSN", "severity": "critical"}
        result = calculate_privacy_score([entity])
        assert result["score"] == 30
        assert result["severity_counts"]["CRITICAL"] == 1

    def test_pydantic_model_input(self):
        pydantic_entity = DetectedEntity(
            text="alice@example.com",
            entity_type="EMAIL",
            severity="HIGH",
        )
        result = calculate_privacy_score([pydantic_entity])
        assert result["score"] == 20
        assert result["total_entities"] == 1

    def test_custom_class_input(self):
        custom_obj = CustomEntityObj(
            text="456-78-9012",
            entity_type="SSN",
            severity="CRITICAL",
        )
        result = calculate_privacy_score([custom_obj])
        assert result["score"] == 30
        assert result["risk_level"] == "MEDIUM"


# ==============================================================================
# PART 2: DOCUMENT PROTECTION TESTS
# ==============================================================================

class TestRedactMode:
    """Verifies REDACT replacement behaviors."""

    def test_redact_one_entity(self):
        text = "Contact me at john@example.com anytime."
        entities = [{
            "entity_type": "EMAIL",
            "text": "john@example.com",
            "start": 14,
            "end": 30,
        }]
        result = redact_text(text, entities)
        assert result == "Contact me at [REDACTED: EMAIL] anytime."

    def test_redact_multiple_entities(self):
        text = "Alice called Bob at 555-1234."
        entities = [
            {"entity_type": "NAME", "text": "Alice", "start": 0, "end": 5},
            {"entity_type": "NAME", "text": "Bob", "start": 13, "end": 16},
            {"entity_type": "PHONE", "text": "555-1234", "start": 20, "end": 28},
        ]
        result = redact_text(text, entities)
        assert result == "[REDACTED: PERSON] called [REDACTED: PERSON] at [REDACTED: PHONE]."

    def test_redact_generic_pii(self):
        text = "Secret code is XYZ."
        entities = [{"entity_type": "", "text": "XYZ", "start": 15, "end": 18}]
        result = redact_text(text, entities)
        assert result == "Secret code is [REDACTED]."


class TestMaskMode:
    """Verifies MASK replacement behaviors for various data types."""

    def test_mask_email(self):
        text = "My email is john@example.com."
        entities = [{"entity_type": "EMAIL", "text": "john@example.com", "start": 12, "end": 28}]
        result = mask_text(text, entities)
        assert result == "My email is j***@example.com."

    def test_mask_phone_10_digits(self):
        text = "Call 9876543210 now."
        entities = [{"entity_type": "PHONE", "text": "9876543210", "start": 5, "end": 15}]
        result = mask_text(text, entities)
        assert result == "Call ******3210 now."

    def test_mask_credit_card(self):
        text = "Card: 1234-5678-9012-3456 on file."
        entities = [{"entity_type": "CREDIT_CARD", "text": "1234-5678-9012-3456", "start": 6, "end": 25}]
        result = mask_text(text, entities)
        assert result == "Card: ****-****-****-3456 on file."

    def test_mask_ssn(self):
        text = "SSN: 123-45-6789."
        entities = [{"entity_type": "SSN", "text": "123-45-6789", "start": 5, "end": 16}]
        result = mask_text(text, entities)
        assert result == "SSN: ***-**-6789."

    def test_mask_name(self):
        text = "Hello John Smith."
        entities = [{"entity_type": "NAME", "text": "John Smith", "start": 6, "end": 16}]
        result = mask_text(text, entities)
        assert result == "Hello J*** S***."

    def test_mask_address(self):
        text = "Located at 123 Main St."
        entities = [{"entity_type": "ADDRESS", "text": "123 Main St", "start": 11, "end": 22}]
        result = mask_text(text, entities)
        assert result == "Located at *** Main St."

    def test_mask_unknown_entity_generic(self):
        text = "Token: ABCDEFGHIJKLMNOP"
        entities = [{"entity_type": "SECRET_KEY", "text": "ABCDEFGHIJKLMNOP", "start": 7, "end": 23}]
        result = mask_text(text, entities)
        assert result.startswith("Token: A***")
        assert result.endswith("P")


class TestAnonymizeMode:
    """Verifies ANONYMIZE mode consistency and placeholder generation."""

    def test_repeated_entity_gets_same_placeholder(self):
        text = "John Smith works at X. Contact John Smith at desk 4."
        entities = [
            {"entity_type": "NAME", "text": "John Smith", "start": 0, "end": 10},
            {"entity_type": "NAME", "text": "John Smith", "start": 31, "end": 41},
        ]
        result = anonymize_text(text, entities)
        assert result == "[PERSON_1] works at X. Contact [PERSON_1] at desk 4."

    def test_different_entity_values_get_different_placeholders(self):
        text = "Alice met Bob and then Alice spoke to Charlie."
        entities = [
            {"entity_type": "NAME", "text": "Alice", "start": 0, "end": 5},
            {"entity_type": "NAME", "text": "Bob", "start": 10, "end": 13},
            {"entity_type": "NAME", "text": "Alice", "start": 23, "end": 28},
            {"entity_type": "NAME", "text": "Charlie", "start": 38, "end": 45},
        ]
        result = anonymize_text(text, entities)
        assert result == "[PERSON_1] met [PERSON_2] and then [PERSON_1] spoke to [PERSON_3]."

    def test_multiple_entity_types_anonymization(self):
        text = "User John Doe has email john@example.com and phone 9876543210."
        entities = [
            {"entity_type": "NAME", "text": "John Doe", "start": 5, "end": 13},
            {"entity_type": "EMAIL", "text": "john@example.com", "start": 24, "end": 40},
            {"entity_type": "PHONE", "text": "9876543210", "start": 51, "end": 61},
        ]
        result = anonymize_text(text, entities)
        assert result == "User [PERSON_1] has email [EMAIL_1] and phone [PHONE_1]."


class TestSafeTextReplacement:
    """Verifies boundary cases, offsets, overlaps, and empty cases."""

    def test_no_detected_entities_returns_original_text(self):
        text = "This is completely safe public text."
        assert protect_document(text, [], mode="redact") == text
        assert protect_document(text, None, mode="mask") == text
        assert protect_document(text, [], mode="anonymize") == text

    def test_empty_string_input(self):
        assert protect_document("", []) == ""

    def test_overlapping_entities_handled_gracefully(self):
        # Entity 1 covers "John Doe", Entity 2 covers "John" inside it
        text = "Employee John Doe joined today."
        entities = [
            {"entity_type": "NAME", "text": "John Doe", "start": 9, "end": 17},
            {"entity_type": "NAME", "text": "John", "start": 9, "end": 13},
        ]
        # Should keep longer match "John Doe" and avoid corrupted text
        result = redact_text(text, entities)
        assert result == "Employee [REDACTED: PERSON] joined today."

    def test_duplicate_detections_handled(self):
        text = "Contact 555-9999 please."
        entities = [
            {"entity_type": "PHONE", "text": "555-9999", "start": 8, "end": 16},
            {"entity_type": "PHONE", "text": "555-9999", "start": 8, "end": 16},
        ]
        result = redact_text(text, entities)
        assert result == "Contact [REDACTED: PHONE] please."

    def test_invalid_offsets_fallback_to_text_search(self):
        text = "Email me at support@privacy.org for help."
        # Missing start/end offsets, but valid text is provided
        entities = [{"entity_type": "EMAIL", "text": "support@privacy.org"}]
        result = redact_text(text, entities)
        assert result == "Email me at [REDACTED: EMAIL] for help."

    def test_malformed_out_of_bounds_offsets(self):
        text = "Safe document."
        entities = [
            {"entity_type": "NAME", "text": "Ghost", "start": -5, "end": 2},
            {"entity_type": "NAME", "text": "OutOfBounds", "start": 50, "end": 100},
            {"entity_type": "NAME", "text": "Inverted", "start": 10, "end": 5},
            {"entity_type": "NAME", "text": "InvalidType", "start": "bad", "end": "data"},
        ]
        # Must not crash, should return original text safely
        result = redact_text(text, entities)
        assert result == text

    def test_pydantic_entities_in_protection(self):
        text = "Reach Bob at 1234567890."
        entities = [
            DetectedEntity(text="Bob", entity_type="NAME", start=6, end=9),
            DetectedEntity(text="1234567890", entity_type="PHONE", start=13, end=23),
        ]
        result = mask_text(text, entities)
        assert result == "Reach B*** at ******7890."


class TestIntegrationDetails:
    """Verifies detailed protector output including mappings."""

    def test_protector_detailed_output(self):
        text = "Contact John at john@example.com. Again, John is here."
        entities = [
            {"entity_type": "NAME", "text": "John", "start": 8, "end": 12},
            {"entity_type": "EMAIL", "text": "john@example.com", "start": 16, "end": 32},
            {"entity_type": "NAME", "text": "John", "start": 41, "end": 45},
        ]
        protector = DocumentProtector()
        details = protector.protect(text, entities, mode="anonymize")

        assert details["mode"] == "anonymize"
        assert details["entities_protected"] == 3
        assert "[PERSON_1]" in details["protected_text"]
        assert "[EMAIL_1]" in details["protected_text"]
        assert details["anonymization_mapping"]["john"] == "[PERSON_1]"
        assert details["anonymization_mapping"]["john@example.com"] == "[EMAIL_1]"
