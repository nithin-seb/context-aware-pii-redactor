"""Comprehensive test suite for PrivacyLens backend covering all test requirements A through L."""

import io
import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import docx
from fastapi.testclient import TestClient
import pymupdf

from main import app, scan_cache
from services.document_parser import (
    EmptyDocumentError,
    FileTooLargeError,
    UnsupportedFileTypeError,
    extract_document,
)
from services.entity_merger import merge_entities
from services.gemini import GeminiService, detect_gemini_pii
from services.local_detector import detect_local_pii
from services.privacy_score import calculate_privacy_score
from services.protection import protect_document


def create_sample_pdf_bytes(text: str) -> bytes:
    """Helper to generate an in-memory PDF for testing."""
    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text((50, 72), text, fontsize=12)
    pdf_bytes = doc.tobytes()
    doc.close()
    return pdf_bytes


def create_sample_docx_bytes(paragraphs: list, table_data: list = None) -> bytes:
    """Helper to generate an in-memory DOCX for testing."""
    doc = docx.Document()
    for p in paragraphs:
        doc.add_paragraph(p)
    if table_data:
        table = doc.add_table(rows=len(table_data), cols=len(table_data[0]))
        for r_idx, row in enumerate(table_data):
            for c_idx, val in enumerate(row):
                table.cell(r_idx, c_idx).text = val
    stream = io.BytesIO()
    doc.save(stream)
    return stream.getvalue()


class PrivacyLensBackendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    # --- Test A: /health ---
    def test_a_health_check(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})
        print("[PASSED] Test A Passed: /health endpoint returns status ok")

    # --- Test B: PDF extraction ---
    def test_b_pdf_extraction(self):
        sample_text = "PrivacyLens Confidential Report.\nPatient: John Doe, Email: john.doe@example.com"
        pdf_bytes = create_sample_pdf_bytes(sample_text)
        result = extract_document(pdf_bytes, "report.pdf", "application/pdf")
        self.assertEqual(result["file_type"], "pdf")
        self.assertIn("John Doe", result["text"])
        self.assertIn("john.doe@example.com", result["text"])
        print("[PASSED] Test B Passed: PDF text extraction verified")

    # --- Test C: DOCX extraction ---
    def test_c_docx_extraction(self):
        paragraphs = ["Employee Onboarding Form", "Name: Alice Smith", "Contact: +91 9876543210"]
        table = [["PAN", "ABCDE1234F"], ["Aadhaar", "2345 6789 0123"]]
        docx_bytes = create_sample_docx_bytes(paragraphs, table)
        result = extract_document(docx_bytes, "employee.docx")
        self.assertEqual(result["file_type"], "docx")
        self.assertIn("Alice Smith", result["text"])
        self.assertIn("ABCDE1234F", result["text"])
        self.assertIn("2345 6789 0123", result["text"])
        print("[PASSED] Test C Passed: DOCX text & table extraction verified")

    # --- Test D: TXT extraction and edge cases ---
    def test_d_txt_extraction_and_edge_cases(self):
        txt_bytes = "Plain text document with API Key: AKIAIOSFODNN7EXAMPLE".encode("utf-8")
        result = extract_document(txt_bytes, "notes.txt", "text/plain")
        self.assertEqual(result["file_type"], "txt")
        self.assertIn("AKIAIOSFODNN7EXAMPLE", result["text"])

        # Test Empty Document Error
        with self.assertRaises(EmptyDocumentError):
            extract_document(b"   \n\n  ", "empty.txt")

        # Test Unsupported File Type
        with self.assertRaises(UnsupportedFileTypeError):
            extract_document(b"binary data", "image.png", "image/png")

        # Test File Too Large Error
        large_bytes = b"a" * (11 * 1024 * 1024)
        with self.assertRaises(FileTooLargeError):
            extract_document(large_bytes, "big.txt")

        print("[PASSED] Test D Passed: TXT extraction and validation errors verified")

    # --- Test E: Local PII Detection ---
    def test_e_local_detection(self):
        text = (
            "Contact Alice at alice.smith@privacylens.io or call +91 9876543210 or (555) 123-4567. "
            "Aadhaar: 2345 6789 0123, PAN Card: ABCDE1234F. "
            "UPI: payment.user@okhdfcbank, Account Number: 123456789012. "
            "Database password: SuperSecretMasterPassword123! and AWS key: AKIAIOSFODNN7EXAMPLE"
        )
        entities = detect_local_pii(text)
        types_found = {e["type"] for e in entities}

        self.assertIn("EMAIL", types_found)
        self.assertIn("PHONE", types_found)
        self.assertIn("AADHAAR", types_found)
        self.assertIn("PAN", types_found)
        self.assertIn("FINANCIAL_ID", types_found)
        self.assertIn("CREDENTIAL", types_found)

        # Verify no passwords or keys leaked in logs / values properly identified
        self.assertTrue(any(e["value"] == "alice.smith@privacylens.io" for e in entities))
        self.assertTrue(any("9876543210" in e["value"] for e in entities))
        self.assertTrue(any(e["value"] == "ABCDE1234F" for e in entities))
        self.assertTrue(any("2345 6789 0123" in e["value"] for e in entities))
        self.assertTrue(any(e["type"] == "CREDENTIAL" and "SuperSecretMasterPassword123!" in e["value"] for e in entities))

        print(f"[PASSED] Test E Passed: Local detection identified all {len(types_found)} expected PII types")

    # --- Test F: Gemini Detection with Mock / Valid Schema ---
    def test_f_gemini_detection(self):
        mock_response_json = json.dumps({
            "risk_level": "CRITICAL",
            "summary": "Document contains sensitive patient medical records and private addresses.",
            "entities": [
                {
                    "type": "PERSON_NAME",
                    "value": "Jane Roe",
                    "risk": "HIGH",
                    "reason": "Patient full legal name.",
                    "recommended_action": "Redact name.",
                },
                {
                    "type": "MEDICAL",
                    "value": "Acute Type 1 Diabetes with Insulin Regimen",
                    "risk": "CRITICAL",
                    "reason": "Protected health condition (HIPAA/DPDP sensitive).",
                    "recommended_action": "Redact medical diagnosis.",
                },
                {
                    "type": "ADDRESS",
                    "value": "456 Elm Street, Apt 7B, Seattle, WA",
                    "risk": "HIGH",
                    "reason": "Residential home address.",
                    "recommended_action": "Mask street details.",
                }
            ]
        })

        service = GeminiService(api_key="mock-api-key")
        parsed = service._parse_and_validate_response(mock_response_json)
        self.assertTrue(parsed["success"])
        self.assertEqual(parsed["risk_level"], "CRITICAL")
        self.assertEqual(len(parsed["entities"]), 3)
        self.assertEqual(parsed["entities"][0]["type"], "PERSON_NAME")
        self.assertEqual(parsed["entities"][1]["type"], "MEDICAL")
        print("[PASSED] Test F Passed: Gemini structured detection schema parsed and validated")

    # --- Test G: Gemini Failure Fallback ---
    def test_g_gemini_failure_fallback(self):
        # When API key is not configured or fails
        service = GeminiService(api_key="")
        result = service.detect_pii("Sample document")
        self.assertFalse(result["success"])
        self.assertIn("error", result)
        self.assertEqual(result["entities"], [])

        # End-to-end /scan must continue gracefully even if Gemini fails
        sample_doc = "Email: emergency@hospital.org, Phone: 9876543210"
        files = {"file": ("test.txt", io.BytesIO(sample_doc.encode("utf-8")), "text/plain")}
        response = self.client.post("/scan", files=files)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("scan_id", data)
        self.assertGreaterEqual(len(data["entities"]), 2)
        print("[PASSED] Test G Passed: Gemini failure falls back gracefully to local detections")

    # --- Test H: Malformed Gemini response handling ---
    def test_h_malformed_gemini_response_handling(self):
        service = GeminiService()

        # Test case 1: Raw text / non-json
        res1 = service._parse_and_validate_response("I detected some names like John Doe.")
        self.assertFalse(res1["success"])
        self.assertEqual(res1["entities"], [])

        # Test case 2: Markdown wrapped JSON
        res2 = service._parse_and_validate_response("```json\n{\"risk_level\": \"LOW\", \"summary\": \"Clean\", \"entities\": []}\n```")
        self.assertTrue(res2["success"])
        self.assertEqual(res2["risk_level"], "LOW")

        # Test case 3: JSON with unexpected types or missing fields
        res3 = service._parse_and_validate_response(json.dumps({
            "risk_level": "INVALID_RISK",
            "entities": [{"type": "UNKNOWN_CUSTOM_TYPE", "value": "test_val"}]
        }))
        self.assertTrue(res3["success"])
        self.assertEqual(res3["risk_level"], "LOW")
        self.assertEqual(res3["entities"][0]["type"], "OTHER_PII")
        print("[PASSED] Test H Passed: Malformed and edge-case Gemini responses handled safely")

    # --- Test I: Duplicate Local + Gemini Entity Merging ---
    def test_i_duplicate_merging(self):
        local_entities = [
            {
                "type": "EMAIL",
                "value": "alice@example.com",
                "risk": "HIGH",
                "reason": "Email address pattern match.",
                "recommended_action": "Mask or redact email.",
            },
            {
                "type": "PAN",
                "value": "ABCDE1234F",
                "risk": "CRITICAL",
                "reason": "PAN card pattern.",
                "recommended_action": "Redact PAN.",
            }
        ]

        gemini_entities = [
            # Duplicate email with generic classification and richer reason
            {
                "type": "OTHER_PII",
                "value": "alice@example.com",
                "risk": "MEDIUM",
                "reason": "User primary contact email address.",
                "recommended_action": "Redact email before sharing outside domain.",
            },
            # Unique Gemini entity
            {
                "type": "PERSON_NAME",
                "value": "Alice Henderson",
                "risk": "HIGH",
                "reason": "Full legal name of candidate.",
                "recommended_action": "Redact name for blind review.",
            }
        ]

        merged = merge_entities(local_entities, gemini_entities)
        self.assertEqual(len(merged), 3)

        # Check deduplicated email
        email_entity = next(e for e in merged if e["value"] == "alice@example.com")
        self.assertEqual(email_entity["type"], "EMAIL")  # Kept specific type
        self.assertEqual(email_entity["risk"], "HIGH")   # Kept higher risk
        self.assertEqual(email_entity["source"], "local+gemini")
        self.assertEqual(email_entity["reason"], "User primary contact email address.")

        # Check unique entities
        pan_entity = next(e for e in merged if e["value"] == "ABCDE1234F")
        self.assertEqual(pan_entity["source"], "local")

        name_entity = next(e for e in merged if e["value"] == "Alice Henderson")
        self.assertEqual(name_entity["source"], "gemini")

        print("[PASSED] Test I Passed: Duplicate entity deduplication and source merging verified")

    # --- Test J: /scan End-to-End ---
    def test_j_scan_end_to_end(self):
        # 1. TXT upload
        txt_content = "Confidential report for Bob Smith. Email: bob.smith@work.com, Phone: +91 9988776655. Aadhaar: 3456 7890 1234."
        files = {"file": ("audit.txt", io.BytesIO(txt_content.encode("utf-8")), "text/plain")}
        data = {"purpose": "Compliance review"}
        response = self.client.post("/scan", files=files, data=data)
        self.assertEqual(response.status_code, 200)
        json_data = response.json()
        self.assertIn("scan_id", json_data)
        self.assertGreater(json_data["risk_score"], 0)
        self.assertIn(json_data["risk_level"], ["LOW", "MEDIUM", "HIGH", "CRITICAL"])
        self.assertIsInstance(json_data["entities"], list)
        self.assertGreaterEqual(len(json_data["entities"]), 3)

        # 2. DOCX upload
        docx_bytes = create_sample_docx_bytes(["Confidential doc", "Email: ceo@company.com"])
        files_docx = {"file": ("executive.docx", io.BytesIO(docx_bytes), "application/vnd.openxmlformats-officedocument.wordprocessingml.document")}
        res_docx = self.client.post("/scan", files=files_docx)
        self.assertEqual(res_docx.status_code, 200)

        # 3. PDF upload
        pdf_bytes = create_sample_pdf_bytes("Confidential Statement. Phone: 9876543210, PAN: ABCDE1234F")
        files_pdf = {"file": ("statement.pdf", io.BytesIO(pdf_bytes), "application/pdf")}
        res_pdf = self.client.post("/scan", files=files_pdf)
        self.assertEqual(res_pdf.status_code, 200)

        print("[PASSED] Test J Passed: /scan end-to-end verified with TXT, DOCX, and PDF uploads")

    # --- Test K: Person 2 Privacy Score Integration ---
    def test_k_privacy_score_integration(self):
        # Empty
        res_empty = calculate_privacy_score([], "Clean document text")
        self.assertEqual(res_empty["risk_score"], 0)
        self.assertEqual(res_empty["risk_level"], "LOW")

        # Critical entity presence (weight 30 -> MEDIUM risk level under standard 0-20/21-50/51-75/76-100 scale)
        entities_critical = [{"type": "CREDENTIAL", "risk": "CRITICAL"}]
        res_critical = calculate_privacy_score(entities_critical, "doc text")
        self.assertEqual(res_critical["risk_level"], "MEDIUM")
        self.assertEqual(res_critical["risk_score"], 30)

        # High risk combination (3 critical entities = 90 -> CRITICAL)
        entities_heavy = [
            {"type": "CREDENTIAL", "risk": "CRITICAL"},
            {"type": "AADHAAR", "risk": "CRITICAL"},
            {"type": "PAN", "risk": "CRITICAL"},
        ]
        res_heavy = calculate_privacy_score(entities_heavy, "doc text")
        self.assertEqual(res_heavy["risk_level"], "CRITICAL")
        self.assertEqual(res_heavy["risk_score"], 90)

        # Multiple entities (EMAIL: 20, PHONE: 20, PERSON: 10, ADDRESS: 10 = 60 -> HIGH)
        entities_multi = [
            {"type": "EMAIL", "risk": "HIGH"},
            {"type": "PHONE", "risk": "HIGH"},
            {"type": "PERSON_NAME", "risk": "MEDIUM"},
            {"type": "ADDRESS", "risk": "MEDIUM"},
        ]
        res_multi = calculate_privacy_score(entities_multi, "doc text")
        self.assertEqual(res_multi["risk_level"], "HIGH")
        self.assertEqual(res_multi["risk_score"], 60)

        print("[PASSED] Test K Passed: Privacy score calculation interface verified")

    # --- Test L: /protect with REDACT, MASK, ANONYMIZE ---
    def test_l_protect_modes(self):
        doc_text = "Executive Briefing: Contact Jane Doe at jane@defense.gov or +1-800-555-0199. Aadhaar: 2345 6789 0123."
        files = {"file": ("briefing.txt", io.BytesIO(doc_text.encode("utf-8")), "text/plain")}
        scan_res = self.client.post("/scan", files=files)
        self.assertEqual(scan_res.status_code, 200)
        scan_id = scan_res.json()["scan_id"]

        # 1. Test REDACT
        redact_res = self.client.post("/protect", json={"scan_id": scan_id, "mode": "REDACT"})
        self.assertEqual(redact_res.status_code, 200)
        self.assertIn("attachment; filename=", redact_res.headers.get("Content-Disposition", ""))
        redacted_text = redact_res.content.decode("utf-8")
        self.assertNotIn("jane@defense.gov", redacted_text)
        self.assertIn("[REDACTED: EMAIL]", redacted_text)

        # 2. Test MASK
        mask_res = self.client.post("/protect", json={"scan_id": scan_id, "mode": "MASK"})
        self.assertEqual(mask_res.status_code, 200)
        masked_text = mask_res.content.decode("utf-8")
        self.assertNotIn("jane@defense.gov", masked_text)
        self.assertIn("@defense.gov", masked_text)

        # 3. Test ANONYMIZE
        anon_res = self.client.post("/protect", json={"scan_id": scan_id, "mode": "ANONYMIZE"})
        self.assertEqual(anon_res.status_code, 200)
        anon_text = anon_res.content.decode("utf-8")
        self.assertNotIn("jane@defense.gov", anon_text)
        self.assertIn("@privacylens.internal", anon_text)

        # 4. Test Invalid Scan ID
        invalid_scan_res = self.client.post("/protect", json={"scan_id": "non-existent-id", "mode": "REDACT"})
        self.assertEqual(invalid_scan_res.status_code, 404)

        # 5. Test Invalid Mode
        invalid_mode_res = self.client.post("/protect", json={"scan_id": scan_id, "mode": "DESTROY"})
        self.assertEqual(invalid_mode_res.status_code, 400)

        # 6. Test PDF and DOCX protection
        pdf_bytes = create_sample_pdf_bytes("Confidential PDF. Contact: user@finance.com")
        scan_pdf_res = self.client.post("/scan", files={"file": ("doc.pdf", io.BytesIO(pdf_bytes), "application/pdf")})
        pdf_scan_id = scan_pdf_res.json()["scan_id"]
        pdf_protect_res = self.client.post("/protect", json={"scan_id": pdf_scan_id, "mode": "REDACT"})
        self.assertEqual(pdf_protect_res.status_code, 200)
        self.assertEqual(pdf_protect_res.headers.get("content-type"), "application/pdf")

        print("[PASSED] Test L Passed: /protect verified with REDACT, MASK, ANONYMIZE across TXT and PDF formats")


if __name__ == "__main__":
    unittest.main(verbosity=2)
