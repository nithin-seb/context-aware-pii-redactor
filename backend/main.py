"""PrivacyLens Backend - Context-Aware PII Redaction and Privacy Analysis Engine."""

import logging
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional
import dotenv

# Ensure backend directory is in sys.path
backend_dir = str(Path(__file__).resolve().parent)
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

# Load environment configuration
dotenv.load_dotenv()
dotenv.load_dotenv(os.path.join(backend_dir, ".env"))
dotenv.load_dotenv(os.path.join(backend_dir, "..", ".env.local"))

from fastapi import FastAPI, File, Form, HTTPException, Request, Response, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from services.document_parser import (
    DocumentParserError,
    EmptyDocumentError,
    ExtractionError,
    FileTooLargeError,
    UnsupportedFileTypeError,
    extract_document,
)
from services.entity_merger import merge_entities
from services.gemini import detect_gemini_pii
from services.local_detector import detect_local_pii
from services.privacy_score import calculate_privacy_score
from services.protection import ProtectionError, protect_document

# Configure logging (safe formatting - no sensitive data)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("privacylens.api")


# In-memory transient scan store with TTL
class ScanCache:
    """Process-local temporary in-memory scan cache with automatic TTL expiry."""

    def __init__(self, ttl_seconds: int = 1800, max_items: int = 500):
        self._cache: Dict[str, Dict[str, Any]] = {}
        self.ttl_seconds = ttl_seconds
        self.max_items = max_items

    def cleanup(self):
        """Remove expired entries."""
        now = time.time()
        expired_keys = [k for k, v in self._cache.items() if now - v.get("created_at", 0) > self.ttl_seconds]
        for k in expired_keys:
            self._cache.pop(k, None)

    def set(self, scan_id: str, data: Dict[str, Any]):
        """Store scan record."""
        self.cleanup()
        if len(self._cache) >= self.max_items:
            # Evict oldest entry
            oldest_key = min(self._cache.keys(), key=lambda k: self._cache[k].get("created_at", 0))
            self._cache.pop(oldest_key, None)

        data["created_at"] = time.time()
        self._cache[scan_id] = data

    def get(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve scan record if still valid."""
        self.cleanup()
        entry = self._cache.get(scan_id)
        if not entry:
            return None
        return entry


scan_cache = ScanCache()

# FastAPI application instance
app = FastAPI(
    title="PrivacyLens API",
    description="Context-Aware PII Redaction and Privacy Analysis Engine",
    version="1.0.0",
)

# CORS Configuration
allowed_origins_env = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000")
allowed_origins = [o.strip() for o in allowed_origins_env.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition"],
)


# Pydantic Schemas
class EntityResponse(BaseModel):
    type: str
    value: str
    risk: str
    reason: str
    recommended_action: str
    source: str


class ScanResponse(BaseModel):
    scan_id: str
    risk_score: int
    risk_level: str
    summary: str
    entities: List[EntityResponse]


class ProtectRequest(BaseModel):
    scan_id: str = Field(..., description="ID of the completed scan")
    mode: str = Field(..., description="Protection mode: REDACT, MASK, or ANONYMIZE")


# Global Exception Handlers
@app.exception_handler(UnsupportedFileTypeError)
async def unsupported_file_handler(request: Request, exc: UnsupportedFileTypeError):
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": str(exc), "error_type": "UNSUPPORTED_FILE_TYPE"},
    )


@app.exception_handler(FileTooLargeError)
async def file_too_large_handler(request: Request, exc: FileTooLargeError):
    return JSONResponse(
        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
        content={"detail": str(exc), "error_type": "FILE_TOO_LARGE"},
    )


@app.exception_handler(EmptyDocumentError)
async def empty_document_handler(request: Request, exc: EmptyDocumentError):
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": str(exc), "error_type": "EMPTY_DOCUMENT"},
    )


@app.exception_handler(ExtractionError)
async def extraction_error_handler(request: Request, exc: ExtractionError):
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": str(exc), "error_type": "EXTRACTION_FAILURE"},
    )


@app.exception_handler(ProtectionError)
async def protection_error_handler(request: Request, exc: ProtectionError):
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": str(exc), "error_type": "PROTECTION_FAILURE"},
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled error processing request: %s", type(exc).__name__)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An unexpected error occurred while processing the document.", "error_type": "INTERNAL_SERVER_ERROR"},
    )


# API Routes
@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint."""
    return {"status": "ok"}


@app.post("/scan", response_model=ScanResponse, tags=["PII Detection"])
async def scan_document(
    file: UploadFile = File(...),
    purpose: Optional[str] = Form(None),
):
    """
    Scan an uploaded document (PDF, DOCX, TXT) for PII using local deterministic rules + Gemini AI.
    """
    if not file.filename:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No file selected for upload.")

    logger.info("Received scan request for file: %s", os.path.basename(file.filename))

    try:
        file_bytes = await file.read()
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Failed to read uploaded file.")

    # 1. Document Extraction & Validation
    doc_data = extract_document(
        file_bytes=file_bytes,
        filename=file.filename,
        content_type=file.content_type,
    )
    doc_text = doc_data["text"]

    # 2. Local Deterministic PII Detection
    local_entities = detect_local_pii(doc_text)

    # 3. Gemini Contextual PII Detection (Safe failure fallback)
    gemini_result = detect_gemini_pii(doc_text, purpose)
    gemini_entities = gemini_result.get("entities", [])
    gemini_summary = gemini_result.get("summary")
    gemini_risk = gemini_result.get("risk_level")

    # 4. Merge & Deduplicate Entities
    merged_entities = merge_entities(local_entities, gemini_entities)

    # 5. Calculate Privacy Score (Person 2 Integration Hook)
    score_result = calculate_privacy_score(
        entities=merged_entities,
        document_text=doc_text,
        gemini_summary=gemini_summary,
        gemini_risk_level=gemini_risk,
    )

    # 6. Generate Scan ID & Store in Transient Cache
    scan_id = str(uuid.uuid4())
    scan_cache.set(
        scan_id,
        {
            "filename": doc_data["filename"],
            "file_type": doc_data["file_type"],
            "raw_bytes": file_bytes,
            "text": doc_text,
            "entities": merged_entities,
            "risk_score": score_result["risk_score"],
            "risk_level": score_result["risk_level"],
            "summary": score_result["summary"],
        },
    )

    logger.info("Completed scan %s: %d entities found, risk %s", scan_id, len(merged_entities), score_result["risk_level"])

    return ScanResponse(
        scan_id=scan_id,
        risk_score=score_result["risk_score"],
        risk_level=score_result["risk_level"],
        summary=score_result["summary"],
        entities=merged_entities,
    )


@app.post("/protect", tags=["Protection & Redaction"])
async def protect_scanned_document(payload: ProtectRequest):
    """
    Generate protected document (REDACT, MASK, or ANONYMIZE) from a completed scan.
    Returns downloadable protected file.
    """
    scan_data = scan_cache.get(payload.scan_id)
    if not scan_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan session not found or expired. Please re-scan your document.",
        )

    mode_upper = payload.mode.upper().strip()
    if mode_upper not in {"REDACT", "MASK", "ANONYMIZE"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid mode. Allowed modes are REDACT, MASK, or ANONYMIZE.",
        )

    protected_bytes, output_filename, mime_type = protect_document(
        scan_data=scan_data,
        mode=mode_upper,
    )

    logger.info("Protected document generated for scan %s with mode %s", payload.scan_id, mode_upper)

    return Response(
        content=protected_bytes,
        media_type=mime_type,
        headers={
            "Content-Disposition": f'attachment; filename="{output_filename}"',
            "Access-Control-Expose-Headers": "Content-Disposition",
        },
    )


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
