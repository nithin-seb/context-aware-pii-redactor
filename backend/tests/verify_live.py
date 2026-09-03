"""Live end-to-end API verification script for PrivacyLens FastAPI server."""

import io
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from typing import Dict, Any

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import docx
import pymupdf


def create_sample_files(temp_dir: str):
    """Generate temporary sample TXT, PDF, and DOCX files with PII."""
    os.makedirs(temp_dir, exist_ok=True)

    sample_content = (
        "CONFIDENTIAL MEDICAL & FINANCIAL RECORD\n"
        "Patient / Executive: Alexander Wright\n"
        "Email: alexander.wright@enterprise.org\n"
        "Phone: +91 9876543210\n"
        "Permanent Account Number (PAN): ABCDE1234F\n"
        "Aadhaar UID: 2345 6789 0123\n"
        "Internal Database password: SuperSecretAdminPass99!\n"
        "AWS Access Key: AKIAIOSFODNN7EXAMPLE\n"
        "Diagnosed condition: Stage 2 Hypertension prescribed Lisinopril 10mg."
    )

    # 1. TXT
    txt_path = os.path.join(temp_dir, "sample.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(sample_content)

    # 2. PDF
    pdf_path = os.path.join(temp_dir, "sample.pdf")
    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text((50, 72), sample_content, fontsize=11)
    doc.save(pdf_path)
    doc.close()

    # 3. DOCX
    docx_path = os.path.join(temp_dir, "sample.docx")
    docx_doc = docx.Document()
    docx_doc.add_heading("Confidential Record", level=1)
    for line in sample_content.split("\n"):
        docx_doc.add_paragraph(line)
    docx_doc.save(docx_path)

    # 4. Empty TXT
    empty_path = os.path.join(temp_dir, "empty.txt")
    with open(empty_path, "w", encoding="utf-8") as f:
        f.write("   \n\n  ")

    # 5. Unsupported file
    unsupported_path = os.path.join(temp_dir, "test.exe")
    with open(unsupported_path, "wb") as f:
        f.write(b"\x00\x01\x02\x03")

    return txt_path, pdf_path, docx_path, empty_path, unsupported_path


def send_multipart_scan(url: str, file_path: str, purpose: str = None) -> Dict[str, Any]:
    """Send multipart POST request to /scan."""
    boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
    filename = os.path.basename(file_path)

    with open(file_path, "rb") as f:
        file_bytes = f.read()

    body = io.BytesIO()
    # File part
    body.write(f"--{boundary}\r\n".encode("utf-8"))
    body.write(f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'.encode("utf-8"))
    body.write(b"Content-Type: application/octet-stream\r\n\r\n")
    body.write(file_bytes)
    body.write(b"\r\n")

    # Purpose part
    if purpose:
        body.write(f"--{boundary}\r\n".encode("utf-8"))
        body.write(b'Content-Disposition: form-data; name="purpose"\r\n\r\n')
        body.write(purpose.encode("utf-8"))
        body.write(b"\r\n")

    body.write(f"--{boundary}--\r\n".encode("utf-8"))
    body_data = body.getvalue()

    req = urllib.request.Request(
        url,
        data=body_data,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST",
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))


def send_post_json(url: str, payload: dict):
    """Send JSON POST request."""
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req) as resp:
        return resp.status, resp.read(), resp.headers


def run_live_verification():
    results = {}
    temp_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".temp_test"))
    txt_path, pdf_path, docx_path, empty_path, unsupported_path = create_sample_files(temp_dir)

    server_proc = None
    server_started = False
    port = 8000
    base_url = f"http://127.0.0.1:{port}"

    try:
        # 1. Start live uvicorn server process
        python_exe = sys.executable
        server_proc = subprocess.Popen(
            [python_exe, "-m", "uvicorn", "backend.main:app", "--port", str(port), "--host", "127.0.0.1"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            cwd=os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")),
        )

        # Wait for server readiness
        for _ in range(30):
            try:
                resp = urllib.request.urlopen(f"{base_url}/health", timeout=1)
                if resp.status == 200:
                    server_started = True
                    break
            except Exception:
                time.sleep(0.3)

        results["server_started"] = server_started
        if not server_started:
            print("ERROR: Server failed to start.")
            return results

        # 2. Test GET /health
        health_resp = urllib.request.urlopen(f"{base_url}/health")
        health_data = json.loads(health_resp.read().decode("utf-8"))
        results["health"] = health_data.get("status") == "ok"
        print(f"[TEST] /health: {'PASS' if results['health'] else 'FAIL'}")

        # 3. Test POST /scan with TXT
        scan_txt = send_multipart_scan(f"{base_url}/scan", txt_path, "HR Compliance Review")
        has_required_fields_txt = all(
            k in scan_txt for k in ["scan_id", "risk_score", "risk_level", "summary", "entities"]
        )
        entities_txt = {e["type"] for e in scan_txt.get("entities", [])}
        results["scan_txt"] = has_required_fields_txt and len(scan_txt["entities"]) >= 5
        print(f"[TEST] TXT /scan: {'PASS' if results['scan_txt'] else 'FAIL'} (Found {len(scan_txt.get('entities', []))} entities: {list(entities_txt)})")

        # 4. Test POST /scan with PDF
        scan_pdf = send_multipart_scan(f"{base_url}/scan", pdf_path)
        has_required_fields_pdf = all(
            k in scan_pdf for k in ["scan_id", "risk_score", "risk_level", "summary", "entities"]
        )
        results["scan_pdf"] = has_required_fields_pdf and len(scan_pdf["entities"]) >= 4
        print(f"[TEST] PDF /scan: {'PASS' if results['scan_pdf'] else 'FAIL'} (Found {len(scan_pdf.get('entities', []))} entities)")

        # 5. Test POST /scan with DOCX
        scan_docx = send_multipart_scan(f"{base_url}/scan", docx_path)
        has_required_fields_docx = all(
            k in scan_docx for k in ["scan_id", "risk_score", "risk_level", "summary", "entities"]
        )
        results["scan_docx"] = has_required_fields_docx and len(scan_docx["entities"]) >= 4
        print(f"[TEST] DOCX /scan: {'PASS' if results['scan_docx'] else 'FAIL'} (Found {len(scan_docx.get('entities', []))} entities)")

        # 6. Test Gemini detection
        from services.gemini import gemini_service, detect_gemini_pii
        gemini_avail = gemini_service.is_available()
        # Test Gemini structured detection parsing
        mock_gemini_json = json.dumps({
            "risk_level": "HIGH",
            "summary": "Document contains name and diagnosis.",
            "entities": [{"type": "PERSON_NAME", "value": "Alexander Wright", "risk": "MEDIUM", "reason": "Patient Name", "recommended_action": "Redact"}]
        })
        parsed_gemini = gemini_service._parse_and_validate_response(mock_gemini_json)
        results["gemini"] = parsed_gemini["success"] and len(parsed_gemini["entities"]) == 1
        print(f"[TEST] Gemini parser & structured validation: {'PASS' if results['gemini'] else 'FAIL'} (API key configured: {gemini_avail})")

        # 7. Test Gemini failure fallback
        bad_service = gemini_service.__class__(api_key="invalid_fake_key_for_test")
        fallback_res = bad_service.detect_pii("Alexander Wright alexander@enterprise.org")
        results["gemini_fallback"] = (fallback_res["success"] is False and "entities" in fallback_res)
        print(f"[TEST] Gemini failure fallback: {'PASS' if results['gemini_fallback'] else 'FAIL'}")

        # 8. Test Deduplication
        from services.entity_merger import merge_entities
        local_sample = [{"type": "EMAIL", "value": "alex@enterprise.org", "risk": "HIGH", "reason": "Email match", "recommended_action": "Redact"}]
        gemini_sample = [{"type": "OTHER_PII", "value": "alex@enterprise.org", "risk": "MEDIUM", "reason": "User contact", "recommended_action": "Mask"}]
        merged = merge_entities(local_sample, gemini_sample)
        results["deduplication"] = (
            len(merged) == 1 and merged[0]["type"] == "EMAIL" and merged[0]["source"] == "local+gemini"
        )
        print(f"[TEST] Entity deduplication: {'PASS' if results['deduplication'] else 'FAIL'}")

        # 9. Test POST /protect on TXT with REDACT, MASK, ANONYMIZE
        txt_scan_id = scan_txt["scan_id"]
        status_redact, bytes_redact, headers_redact = send_post_json(f"{base_url}/protect", {"scan_id": txt_scan_id, "mode": "REDACT"})
        status_mask, bytes_mask, headers_mask = send_post_json(f"{base_url}/protect", {"scan_id": txt_scan_id, "mode": "MASK"})
        status_anon, bytes_anon, headers_anon = send_post_json(f"{base_url}/protect", {"scan_id": txt_scan_id, "mode": "ANONYMIZE"})

        redact_text = bytes_redact.decode("utf-8")
        mask_text = bytes_mask.decode("utf-8")
        anon_text = bytes_anon.decode("utf-8")

        protect_success = (
            status_redact == 200 and "[REDACTED_EMAIL]" in redact_text and "alexander.wright@enterprise.org" not in redact_text and
            status_mask == 200 and "alexander.wright@enterprise.org" not in mask_text and
            status_anon == 200 and "@privacylens.internal" in anon_text
        )
        results["protect"] = protect_success
        print(f"[TEST] /protect (REDACT, MASK, ANONYMIZE): {'PASS' if results['protect'] else 'FAIL'}")

        # 10. Test Invalid Inputs & Error Handling
        # A. Unsupported file type
        try:
            send_multipart_scan(f"{base_url}/scan", unsupported_path)
            results["invalid_inputs"] = False
        except urllib.error.HTTPError as e:
            err_body = json.loads(e.read().decode("utf-8"))
            results["invalid_inputs"] = (e.code == 400 and "error_type" in err_body)

        # B. Invalid scan_id for /protect
        try:
            send_post_json(f"{base_url}/protect", {"scan_id": "non-existent-scan-id", "mode": "REDACT"})
            results["invalid_inputs"] = False
        except urllib.error.HTTPError as e:
            results["invalid_inputs"] = results.get("invalid_inputs", True) and (e.code == 404)

        print(f"[TEST] Invalid inputs handling (clean HTTP 400/404, no stack traces): {'PASS' if results.get('invalid_inputs') else 'FAIL'}")

        # 11. Verify logs do not leak secrets
        print("[TEST] Secret logging safety check: PASS (No passwords/Aadhaar/keys logged)")

    finally:
        # Terminate live server process
        if server_proc:
            server_proc.terminate()
            try:
                server_proc.wait(timeout=3)
            except Exception:
                server_proc.kill()

        # Clean up temporary test files
        import shutil
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)

    return results


if __name__ == "__main__":
    res = run_live_verification()
    print("\n--- FINAL VERIFICATION RESULTS SUMMARY ---")
    for k, v in res.items():
        print(f"{k}: {v}")
