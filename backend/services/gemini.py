"""Gemini AI contextual PII detection and privacy analysis service using the official google-genai SDK."""

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional
import dotenv

# Load environment variables from backend/.env and project root .env/.env.local
dotenv.load_dotenv()
dotenv.load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))
dotenv.load_dotenv(os.path.join(os.path.dirname(__file__), "..", "..", ".env.local"))
dotenv.load_dotenv(os.path.join(os.path.dirname(__file__), "..", "..", ".env"))

logger = logging.getLogger("privacylens.gemini")

DEFAULT_MODEL_NAME = "gemini-2.5-flash"

VALID_ENTITY_TYPES = {
    "PERSON_NAME",
    "EMAIL",
    "PHONE",
    "ADDRESS",
    "AADHAAR",
    "PAN",
    "FINANCIAL_ID",
    "MEDICAL",
    "CREDENTIAL",
    "PASSWORD",
    "API_KEY",
    "LOCATION",
    "ORGANIZATION",
    "OTHER_PII",
}

VALID_RISK_LEVELS = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

SYSTEM_PROMPT = """You are PrivacyLens AI, an enterprise-grade Context-Aware Privacy & PII Redaction Engine.
Your task is to analyze document text and identify all Personally Identifiable Information (PII), sensitive data, credentials, and private personal attributes.

Categories to detect:
- PERSON_NAME: Names of individuals (customers, patients, employees, clients).
- EMAIL: Email addresses.
- PHONE: Contact phone/mobile numbers.
- ADDRESS: Physical residential or mailing street addresses.
- AADHAAR: Indian Aadhaar numbers (12-digit UIDs).
- PAN: Indian Permanent Account Numbers (tax IDs).
- FINANCIAL_ID: Credit/debit card numbers, bank accounts, UPI IDs, IFSC codes, salary details.
- MEDICAL: Health conditions, prescriptions, patient diagnoses, biometric/medical notes.
- CREDENTIAL / PASSWORD / API_KEY: Passwords, private keys, API secrets, session tokens.
- LOCATION: Specific private locations or coordinates.
- ORGANIZATION: Employer, school, or corporate affiliation if privately identifying.
- OTHER_PII: Date of birth, passport number, driving license, IP address, etc.

For each entity:
1. Extract the exact 'value' as it appears in the text.
2. Assign the most specific 'type'.
3. Assign a 'risk' rating: LOW, MEDIUM, HIGH, or CRITICAL.
4. Provide a clear, concise 'reason' for why this data poses a privacy/security risk.
5. Provide a 'recommended_action' (e.g. 'Redact immediately', 'Mask leaving last 4 digits', 'Pseudonymize').

Output strictly valid JSON matching this schema:
{
  "risk_level": "LOW|MEDIUM|HIGH|CRITICAL",
  "summary": "1-2 sentence executive privacy assessment summary of the document",
  "entities": [
    {
      "type": "PERSON_NAME",
      "value": "string",
      "risk": "LOW|MEDIUM|HIGH|CRITICAL",
      "reason": "string",
      "recommended_action": "string"
    }
  ]
}
"""


class GeminiService:
    """Service wrapper for Google Gemini contextual PII detection."""

    def __init__(self, api_key: Optional[str] = None, model_name: Optional[str] = None):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        self.model_name = model_name or os.getenv("GEMINI_MODEL", DEFAULT_MODEL_NAME)
        self._client = None

    def _get_client(self):
        """Lazy initialization of google-genai Client."""
        if not self.api_key:
            self.api_key = os.getenv("GEMINI_API_KEY")

        if not self.api_key:
            return None

        if self._client is None:
            try:
                from google import genai
                self._client = genai.Client(api_key=self.api_key)
            except Exception as e:
                logger.warning("Failed to initialize Google GenAI client: %s", type(e).__name__)
                return None

        return self._client

    def is_available(self) -> bool:
        """Check if Gemini service is properly configured with an API key."""
        return bool(self.api_key or os.getenv("GEMINI_API_KEY"))

    def detect_pii(self, text: str, purpose: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyze text using Gemini contextual AI for PII and sensitive data.

        Args:
            text: Document text to analyze.
            purpose: Optional user-defined intended purpose (e.g. 'Resume review for hiring').

        Returns:
            Dict containing:
                - success: bool
                - risk_level: str
                - summary: str
                - entities: list of entity dicts
                - error: optional error message string
        """
        if not text or not text.strip():
            return {
                "success": True,
                "risk_level": "LOW",
                "summary": "Document contains no text.",
                "entities": [],
            }

        client = self._get_client()
        if not client:
            return {
                "success": False,
                "risk_level": "LOW",
                "summary": "Gemini API key not configured. Using local deterministic detection.",
                "entities": [],
                "error": "GEMINI_API_KEY is not set in environment.",
            }

        prompt_content = f"Document Content to Analyze:\n```\n{text}\n```\n"
        if purpose and purpose.strip():
            prompt_content += (
                f"\nContext / Intended Purpose of Data Use:\n\"{purpose.strip()}\"\n"
                "Evaluate whether each piece of PII is necessary for this stated purpose or should be redacted."
            )

        try:
            from google.genai import types

            response = client.models.generate_content(
                model=self.model_name,
                contents=prompt_content,
                config=types.GenerateContentConfig(
                    system_instruction=SYSTEM_PROMPT,
                    response_mime_type="application/json",
                    temperature=0.1,
                ),
            )

            raw_text = response.text or ""
            return self._parse_and_validate_response(raw_text)

        except Exception as e:
            error_msg = f"Gemini analysis encountered an error ({type(e).__name__})"
            logger.warning("Gemini API call failed safely: %s", type(e).__name__)
            return {
                "success": False,
                "risk_level": "LOW",
                "summary": "Gemini contextual analysis unavailable. Falling back to local rules.",
                "entities": [],
                "error": error_msg,
            }

    def _parse_and_validate_response(self, raw_json_text: str) -> Dict[str, Any]:
        """Safely parse and validate JSON output from Gemini."""
        if not raw_json_text or not raw_json_text.strip():
            return {
                "success": False,
                "risk_level": "LOW",
                "summary": "Empty response received from Gemini.",
                "entities": [],
                "error": "Empty model response",
            }

        # Clean markdown wrappers if present
        clean_text = raw_json_text.strip()
        if clean_text.startswith("```json"):
            clean_text = clean_text[7:]
        elif clean_text.startswith("```"):
            clean_text = clean_text[3:]
        if clean_text.endswith("```"):
            clean_text = clean_text[:-3]
        clean_text = clean_text.strip()

        try:
            parsed = json.loads(clean_text)
        except json.JSONDecodeError:
            # Fallback regex extraction if json object is embedded
            match = re.search(r"\{.*\}", clean_text, re.DOTALL)
            if match:
                try:
                    parsed = json.loads(match.group(0))
                except Exception:
                    return {
                        "success": False,
                        "risk_level": "LOW",
                        "summary": "Malformed response format received from model.",
                        "entities": [],
                        "error": "Failed to parse model JSON output",
                    }
            else:
                return {
                    "success": False,
                    "risk_level": "LOW",
                    "summary": "Malformed response format received from model.",
                    "entities": [],
                    "error": "No valid JSON found in model output",
                }

        if not isinstance(parsed, dict):
            return {
                "success": False,
                "risk_level": "LOW",
                "summary": "Invalid response structure received from model.",
                "entities": [],
                "error": "Model response is not a JSON object",
            }

        # Normalize overall risk level
        overall_risk = str(parsed.get("risk_level", "LOW")).upper()
        if overall_risk not in VALID_RISK_LEVELS:
            overall_risk = "LOW"

        summary = str(parsed.get("summary", "Contextual PII analysis completed."))

        # Normalize and filter entities
        raw_entities = parsed.get("entities", [])
        validated_entities: List[Dict[str, Any]] = []

        if isinstance(raw_entities, list):
            for item in raw_entities:
                if not isinstance(item, dict):
                    continue

                value = str(item.get("value", "")).strip()
                if not value:
                    continue

                entity_type = str(item.get("type", "OTHER_PII")).upper().strip()
                if entity_type not in VALID_ENTITY_TYPES:
                    entity_type = "OTHER_PII"

                risk = str(item.get("risk", "MEDIUM")).upper().strip()
                if risk not in VALID_RISK_LEVELS:
                    risk = "MEDIUM"

                reason = str(item.get("reason", f"{entity_type.replace('_', ' ').title()} identified in document."))
                action = str(item.get("recommended_action", "Review and redact sensitive information."))

                validated_entities.append(
                    {
                        "type": entity_type,
                        "value": value,
                        "risk": risk,
                        "reason": reason,
                        "recommended_action": action,
                        "source": "gemini",
                    }
                )

        return {
            "success": True,
            "risk_level": overall_risk,
            "summary": summary,
            "entities": validated_entities,
        }


# Global singleton
gemini_service = GeminiService()


def detect_gemini_pii(text: str, purpose: Optional[str] = None) -> Dict[str, Any]:
    """Convenience function for Gemini detection."""
    return gemini_service.detect_pii(text, purpose)
