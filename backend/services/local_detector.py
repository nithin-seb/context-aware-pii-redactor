"""Local deterministic PII detector using regex rules, heuristics, and validation algorithms."""

import re
from typing import Any, Dict, List, Set, Tuple


def _luhn_checksum_is_valid(card_number_str: str) -> bool:
    """Verify standard Luhn algorithm for credit card numbers."""
    digits = [int(c) for c in card_number_str if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            d = d * 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


class LocalPIIDetector:
    """High-precision local rule-based PII detector."""

    # 1. EMAIL
    EMAIL_PATTERN = re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b",
        re.IGNORECASE,
    )

    # 2. PHONE (International and Indian)
    PHONE_PATTERNS = [
        # Indian Mobile with country code or 0 prefix: +91 9876543210, +91-98765-43210, 09876543210
        re.compile(r"(?:(?:\+91|0091|91|0)[\s\-]?)?[6-9]\d{4}[\s\-]?\d{5}\b"),
        # US/International: (123) 456-7890, 123-456-7890, +1-123-456-7890
        re.compile(r"(?:\+?\d{1,3}[\s\-\.]?)?\(?\d{3}\)?[\s\-\.]\d{3}[\s\-\.]\d{4}\b"),
        # Standard international with '+'
        re.compile(r"\+\d{1,4}[\s\-]?\d{2,4}[\s\-]?\d{3,4}[\s\-]?\d{3,4}\b"),
    ]

    # 3. PAN (Indian Permanent Account Number) - Format: 5 Letters, 4 Digits, 1 Letter
    PAN_PATTERN = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")

    # 4. AADHAAR (Indian 12-digit UID) - Does not start with 0 or 1
    AADHAAR_PATTERN = re.compile(r"\b[2-9]\d{3}[\s\-]?\d{4}[\s\-]?\d{4}\b")

    # 5. IFSC Code (Indian Financial System Code) - 4 letters, 0, 6 alphanumeric
    IFSC_PATTERN = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")

    # 6. UPI ID - e.g. user@okhdfcbank, username@upi, name@paytm
    UPI_PATTERN = re.compile(
        r"\b[a-zA-Z0-9.\-_]{2,64}@(okhdfcbank|okaxis|oksbi|okicici|paytm|upi|ybl|ibl|axl|federal|apl|postbank|barodampay|airtel|sbi|hdfcbank|icici|kotak|axisbank)\b",
        re.IGNORECASE,
    )

    # 7. Credit / Debit Cards (13 to 19 digits formatted)
    CARD_PATTERN = re.compile(r"\b(?:\d{4}[\s\-]?){3}\d{1,4}\b|\b\d{13,19}\b")

    # 8. Bank Account with Context Keyword
    BANK_ACCOUNT_PATTERN = re.compile(
        r"(?i)\b(?:account(?:\s*no|\s*number)?|a/c\s*(?:no)?|acct\s*#?)[\s\:\-]+([0-9]{9,18})\b"
    )

    # 9. CREDENTIALS & SECRETS
    PASSWORD_ASSIGNMENT_PATTERN = re.compile(
        r"(?i)\b(?:password|passwd|pwd|passcode|secret_key|api_secret)[\s\:\=\'\"]+([^\s\'\"\;\,\n]{4,64})",
    )
    API_KEY_PATTERN = re.compile(
        r"(?i)\b(?:api[_\-\s]?key|access[_\-\s]?token|auth[_\-\s]?token|client[_\-\s]?secret)[\s\:\=\'\"]+([A-Za-z0-9_\-\.]{12,128})",
    )
    GENERIC_API_TOKEN_PATTERNS = [
        # AWS Access Key
        re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        # GitHub Personal Access Token
        re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b"),
        # Google API Key
        re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
        # Bearer Token
        re.compile(r"(?i)\bBearer\s+([A-Za-z0-9_\-\.]{20,256})\b"),
        # Private Key block
        re.compile(r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----"),
    ]

    def detect(self, text: str) -> List[Dict[str, Any]]:
        """
        Scan text and return all detected deterministic PII entities.
        """
        if not text:
            return []

        detected_entities: List[Dict[str, Any]] = []
        occupied_spans: List[Tuple[int, int]] = []

        def _is_overlapping(start: int, end: int) -> bool:
            for s, e in occupied_spans:
                if max(start, s) < min(end, e):
                    return True
            return False

        def _add_entity(
            entity_type: str,
            value: str,
            start: int,
            end: int,
            risk: str,
            reason: str,
            recommended_action: str,
        ):
            if _is_overlapping(start, end):
                return
            occupied_spans.append((start, end))
            detected_entities.append(
                {
                    "type": entity_type,
                    "value": value,
                    "start": start,
                    "end": end,
                    "risk": risk,
                    "reason": reason,
                    "recommended_action": recommended_action,
                    "source": "local",
                }
            )

        # 1. Detect Explicit Credentials & Tokens (Highest Priority)
        for pattern in self.GENERIC_API_TOKEN_PATTERNS:
            for match in pattern.finditer(text):
                val = match.group(0)
                _add_entity(
                    entity_type="CREDENTIAL",
                    value=val,
                    start=match.start(),
                    end=match.end(),
                    risk="CRITICAL",
                    reason="Exposed secret token, cryptographic key, or cloud credential detected.",
                    recommended_action="Revoke and rotate credential immediately; redact before sharing.",
                )

        for match in self.PASSWORD_ASSIGNMENT_PATTERN.finditer(text):
            # Capture the password value or the entire statement if needed
            val = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
            start = match.start(1) if match.lastindex and match.lastindex >= 1 else match.start()
            end = match.end(1) if match.lastindex and match.lastindex >= 1 else match.end()
            # Avoid matching boilerplate words like 'true', 'false', 'null', 'string'
            if val.lower() not in {"true", "false", "null", "none", "string", "example", "xxx", "undefined"}:
                _add_entity(
                    entity_type="CREDENTIAL",
                    value=val,
                    start=start,
                    end=end,
                    risk="CRITICAL",
                    reason="Plaintext password assignment detected.",
                    recommended_action="Redact password immediately; store credentials in secure secret managers.",
                )

        for match in self.API_KEY_PATTERN.finditer(text):
            val = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
            start = match.start(1) if match.lastindex and match.lastindex >= 1 else match.start()
            end = match.end(1) if match.lastindex and match.lastindex >= 1 else match.end()
            if val.lower() not in {"your_api_key", "dummy", "api_key_here", "example", "placeholder"}:
                _add_entity(
                    entity_type="CREDENTIAL",
                    value=val,
                    start=start,
                    end=end,
                    risk="CRITICAL",
                    reason="API key / access token assignment detected.",
                    recommended_action="Redact and rotate API key.",
                )

        # 2. Detect PAN Cards (Indian Tax Identification)
        for match in self.PAN_PATTERN.finditer(text):
            pan_val = match.group(0)
            _add_entity(
                entity_type="PAN",
                value=pan_val,
                start=match.start(),
                end=match.end(),
                risk="CRITICAL",
                reason="Indian Permanent Account Number (PAN) detected.",
                recommended_action="Redact or mask PAN to protect financial and tax identity.",
            )

        # 3. Detect Aadhaar Cards (with contextual verification / digit structure)
        for match in self.AADHAAR_PATTERN.finditer(text):
            raw_val = match.group(0)
            digits_only = re.sub(r"\D", "", raw_val)
            if len(digits_only) == 12:
                # Check preceding context for explicit Aadhaar / UID mention or formatted 4-4-4
                is_formatted = " " in raw_val or "-" in raw_val
                pre_ctx = text[max(0, match.start() - 30):match.start()].lower()
                has_context = any(k in pre_ctx for k in ["aadhaar", "aadhar", "uid", "uidai", "id:"])

                # If formatted as 4-4-4 or has keyword context, classify as Aadhaar
                if is_formatted or has_context:
                    _add_entity(
                        entity_type="AADHAAR",
                        value=raw_val,
                        start=match.start(),
                        end=match.end(),
                        risk="CRITICAL",
                        reason="Indian Aadhaar 12-digit unique identity number detected.",
                        recommended_action="Redact or mask first 8 digits as per UIDAI privacy compliance.",
                    )

        # 4. Detect Financial Cards & Bank Accounts
        for match in self.BANK_ACCOUNT_PATTERN.finditer(text):
            acc_val = match.group(1)
            start = match.start(1)
            end = match.end(1)
            _add_entity(
                entity_type="FINANCIAL_ID",
                value=acc_val,
                start=start,
                end=end,
                risk="HIGH",
                reason="Bank account number detected with explicit account context.",
                recommended_action="Mask bank account digits preserving only the last 4 digits.",
            )

        for match in self.IFSC_PATTERN.finditer(text):
            ifsc_val = match.group(0)
            # Only classify if context mentions IFSC or bank
            pre_ctx = text[max(0, match.start() - 25):match.start()].lower()
            if any(k in pre_ctx for k in ["ifsc", "bank", "branch", "code", "rtgs", "neft"]):
                _add_entity(
                    entity_type="FINANCIAL_ID",
                    value=ifsc_val,
                    start=match.start(),
                    end=match.end(),
                    risk="MEDIUM",
                    reason="Indian Bank IFSC branch routing code detected.",
                    recommended_action="Redact or mask branch routing identifier.",
                )

        for match in self.UPI_PATTERN.finditer(text):
            upi_val = match.group(0)
            _add_entity(
                entity_type="FINANCIAL_ID",
                value=upi_val,
                start=match.start(),
                end=match.end(),
                risk="HIGH",
                reason="UPI Virtual Payment Address (VPA) detected.",
                recommended_action="Redact or anonymize UPI identifier to protect payment handle.",
            )

        for match in self.CARD_PATTERN.finditer(text):
            raw_card = match.group(0)
            clean_digits = re.sub(r"\D", "", raw_card)
            if 13 <= len(clean_digits) <= 19 and _luhn_checksum_is_valid(clean_digits):
                _add_entity(
                    entity_type="FINANCIAL_ID",
                    value=raw_card,
                    start=match.start(),
                    end=match.end(),
                    risk="CRITICAL",
                    reason="Credit / Debit card number verified via Luhn algorithm.",
                    recommended_action="Redact immediately; PCI-DSS prohibits storing or transmitting card numbers.",
                )

        # 5. Detect Emails
        for match in self.EMAIL_PATTERN.finditer(text):
            email_val = match.group(0)
            _add_entity(
                entity_type="EMAIL",
                value=email_val,
                start=match.start(),
                end=match.end(),
                risk="HIGH",
                reason="Personal or professional email address detected.",
                recommended_action="Mask or redact email address to prevent phishing and unauthorized contact.",
            )

        # 6. Detect Phone Numbers
        for pattern in self.PHONE_PATTERNS:
            for match in pattern.finditer(text):
                phone_val = match.group(0).strip()
                digits_count = len(re.sub(r"\D", "", phone_val))
                if 10 <= digits_count <= 15:
                    _add_entity(
                        entity_type="PHONE",
                        value=phone_val,
                        start=match.start(),
                        end=match.end(),
                        risk="HIGH",
                        reason="Telephone / mobile contact number detected.",
                        recommended_action="Mask or redact phone number.",
                    )

        # Sort entities by appearance in document
        detected_entities.sort(key=lambda x: x["start"])
        return detected_entities


# Export singleton instance for reuse
local_detector = LocalPIIDetector()


def detect_local_pii(text: str) -> List[Dict[str, Any]]:
    """Convenience function to run deterministic local detection."""
    return local_detector.detect(text)
