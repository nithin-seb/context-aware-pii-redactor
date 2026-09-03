"""Document protection and sanitization service supporting REDACT, MASK, and ANONYMIZE modes."""

import io
import os
import re
from typing import Any, Dict, List, Optional, Tuple
import pymupdf
import docx

VALID_MODES = {"REDACT", "MASK", "ANONYMIZE"}

MIME_TYPES = {
    "pdf": "application/pdf",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "txt": "text/plain; charset=utf-8",
}


class ProtectionError(Exception):
    """Raised when document protection or sanitization fails."""
    pass


def _mask_value(value: str, entity_type: str) -> str:
    """Generate a masked representation of a sensitive value."""
    if not value:
        return "[MASKED]"

    val = value.strip()
    val_len = len(val)

    # Email masking: j***@example.com
    if "@" in val and entity_type.upper() == "EMAIL":
        parts = val.split("@", 1)
        name, domain = parts[0], parts[1]
        if len(name) <= 2:
            masked_name = name[0] + "***" if len(name) > 0 else "***"
        else:
            masked_name = name[0] + ("*" * (len(name) - 2)) + name[-1]
        return f"{masked_name}@{domain}"

    # Phone / ID masking (e.g. Aadhaar / PAN / Card): keep last 4 digits
    digits_only = re.sub(r"\D", "", val)
    if len(digits_only) >= 8 and entity_type.upper() in {"AADHAAR", "PAN", "FINANCIAL_ID", "PHONE"}:
        last4 = digits_only[-4:]
        prefix = "X" * (len(digits_only) - 4)
        if len(digits_only) == 12:  # Aadhaar 4-4-4 style
            return f"XXXX-XXXX-{last4}"
        elif len(digits_only) == 16:  # Card 4-4-4-4 style
            return f"XXXX-XXXX-XXXX-{last4}"
        return f"{prefix}{last4}"

    # Generic short mask
    if val_len <= 3:
        return "***"
    elif val_len <= 6:
        return val[0] + ("*" * (val_len - 1))
    else:
        return val[0] + ("*" * (val_len - 2)) + val[-1]


def _build_replacement_map(
    entities: List[Dict[str, Any]],
    mode: str
) -> Dict[str, str]:
    """
    Build a mapping of original entity value -> protected replacement string.
    Entities are sorted longest-value first to prevent partial substring conflicts.
    """
    replacements: Dict[str, str] = {}
    anonymize_counters: Dict[str, int] = {}

    # Sort entities by value length descending
    sorted_entities = sorted(
        entities,
        key=lambda x: len(str(x.get("value", ""))),
        reverse=True,
    )

    for entity in sorted_entities:
        orig_val = str(entity.get("value", "")).strip()
        if not orig_val or orig_val in replacements:
            continue

        entity_type = str(entity.get("type", "PII")).upper()

        if mode == "REDACT":
            replacement = f"[REDACTED_{entity_type}]"
        elif mode == "MASK":
            replacement = _mask_value(orig_val, entity_type)
        elif mode == "ANONYMIZE":
            counter = anonymize_counters.get(entity_type, 1)
            anonymize_counters[entity_type] = counter + 1

            if entity_type == "PERSON_NAME":
                replacement = f"[Person_{counter}]"
            elif entity_type == "EMAIL":
                replacement = f"user{counter}@privacylens.internal"
            elif entity_type == "PHONE":
                replacement = f"+1-555-01{counter:02d}"
            elif entity_type == "ADDRESS":
                replacement = f"[Address_{counter}]"
            elif entity_type == "ORGANIZATION":
                replacement = f"[Organization_{counter}]"
            else:
                replacement = f"[ANONYMIZED_{entity_type}_{counter}]"
        else:
            replacement = f"[PROTECTED_{entity_type}]"

        replacements[orig_val] = replacement

    return replacements


def _protect_text_string(text: str, replacement_map: Dict[str, str]) -> str:
    """Replace all sensitive entities in a text string."""
    protected = text
    for orig_val, rep in replacement_map.items():
        if orig_val and orig_val in protected:
            # Case-sensitive exact replacement followed by case-insensitive if needed
            protected = protected.replace(orig_val, rep)
    return protected


def protect_txt(raw_bytes: bytes, replacement_map: Dict[str, str]) -> bytes:
    """Sanitize TXT document."""
    for encoding in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            text = raw_bytes.decode(encoding)
            sanitized = _protect_text_string(text, replacement_map)
            return sanitized.encode("utf-8")
        except UnicodeDecodeError:
            continue
    raise ProtectionError("Failed to decode text document for protection.")


def protect_docx(raw_bytes: bytes, replacement_map: Dict[str, str]) -> bytes:
    """Sanitize DOCX document preserving format."""
    try:
        doc = docx.Document(io.BytesIO(raw_bytes))

        # Sanitize paragraphs
        for p in doc.paragraphs:
            for orig_val, rep in replacement_map.items():
                if orig_val in p.text:
                    p.text = p.text.replace(orig_val, rep)

        # Sanitize table cells
        for table in doc.tables:
            for row in table.rows:
                for cell in row.cells:
                    for orig_val, rep in replacement_map.items():
                        if orig_val in cell.text:
                            cell.text = cell.text.replace(orig_val, rep)

        output_stream = io.BytesIO()
        doc.save(output_stream)
        return output_stream.getvalue()
    except Exception as e:
        raise ProtectionError(f"Failed to protect DOCX document: {str(e)}")


def protect_pdf(
    raw_bytes: bytes,
    replacement_map: Dict[str, str],
    mode: str
) -> bytes:
    """Sanitize PDF document using PyMuPDF native redaction annotations."""
    try:
        doc = pymupdf.open(stream=raw_bytes, filetype="pdf")

        for page in doc:
            for orig_val, rep in replacement_map.items():
                if not orig_val:
                    continue
                # Search all occurrences of the entity text on the page
                rects = page.search_for(orig_val)
                for rect in rects:
                    if mode == "REDACT":
                        # Visual black fill redaction box
                        page.add_redact_annot(
                            rect,
                            text=rep,
                            fontsize=9,
                            fill=(0, 0, 0),
                            text_color=(1, 1, 1),
                        )
                    else:
                        # Mask/Anonymize replacement annotation
                        page.add_redact_annot(
                            rect,
                            text=rep,
                            fontsize=9,
                            fill=(0.95, 0.95, 0.95),
                            text_color=(0.1, 0.1, 0.1),
                        )

            # Apply redactions to permanently remove original text stream and draw replacement
            page.apply_redactions()

        output_bytes = doc.tobytes(deflate=True, clean=True)
        doc.close()
        return output_bytes
    except Exception as e:
        if 'doc' in locals() and not doc.is_closed:
            doc.close()
        raise ProtectionError(f"Failed to protect PDF document: {str(e)}")


def protect_document(
    scan_data: Dict[str, Any],
    mode: str
) -> Tuple[bytes, str, str]:
    """
    Execute document protection (REDACT, MASK, or ANONYMIZE).
    Integration point for Person 2's document protection logic.

    Args:
        scan_data: Cached scan dictionary containing raw_bytes, filename, file_type, entities.
        mode: "REDACT" | "MASK" | "ANONYMIZE"

    Returns:
        Tuple of (protected_bytes, output_filename, mime_type)

    Raises:
        ProtectionError
    """
    mode_upper = mode.upper().strip()
    if mode_upper not in VALID_MODES:
        raise ProtectionError(f"Invalid protection mode '{mode}'. Must be REDACT, MASK, or ANONYMIZE.")

    entities = scan_data.get("entities", [])
    file_type = scan_data.get("file_type", "txt").lower()
    filename = scan_data.get("filename", f"document.{file_type}")
    raw_bytes = scan_data.get("raw_bytes")
    doc_text = scan_data.get("text", "")

    if not raw_bytes and doc_text:
        raw_bytes = doc_text.encode("utf-8")
        file_type = "txt"

    if not raw_bytes:
        raise ProtectionError("No document data available for protection.")

    replacement_map = _build_replacement_map(entities, mode_upper)

    base_name, ext = os.path.splitext(filename)
    output_filename = f"{base_name}_{mode_upper.lower()}{ext if ext else f'.{file_type}'}"
    mime_type = MIME_TYPES.get(file_type, "application/octet-stream")

    if file_type == "pdf":
        protected_bytes = protect_pdf(raw_bytes, replacement_map, mode_upper)
    elif file_type == "docx":
        protected_bytes = protect_docx(raw_bytes, replacement_map)
    elif file_type == "txt":
        protected_bytes = protect_txt(raw_bytes, replacement_map)
    else:
        raise ProtectionError(f"Unsupported file type for protection: {file_type}")

    return protected_bytes, output_filename, mime_type
