# 🔐 PrivacyLens

### 🛡️ Context-Aware PII Detection & Privacy Protection

PrivacyLens is a privacy-first document protection system that helps users **detect, understand, and protect sensitive information before sharing a document**.

Instead of relying only on regular expressions, PrivacyLens combines **local deterministic PII detection** with **Google Gemini contextual intelligence** to identify sensitive information that may depend on the surrounding context. Users can upload a document, review detected PII, understand the privacy risk, and download a protected version using **Redact, Mask, or Anonymize** modes.

---

## 🚀 Live Demo

* 🌐 **Try PrivacyLens:** [https://context-aware-pii-redactor.vercel.app](https://context-aware-pii-redactor.vercel.app)
* ⚙️ **Backend API:** [https://privacylens-api-tiof.onrender.com](https://privacylens-api-tiof.onrender.com)
* 💻 **GitHub Repository:** [https://github.com/nithin-seb/context-aware-pii-redactor](https://github.com/nithin-seb/context-aware-pii-redactor)

---

# ✨ Features

### 📄 Document Processing
* Upload **PDF, DOCX, and TXT** documents
* Automatic text extraction
* File type validation
* Maximum upload size protection (10 MB limit)
* Friendly and resilient error handling

### 🔍 Hybrid PII Detection
PrivacyLens uses two complementary detection layers:
* ⚡ **Local rule-based detection** (Regex & deterministic patterns for speed and offline reliability)
* 🧠 **Google Gemini contextual detection** (Context-aware reasoning for unstructured, ambiguous, or role-dependent PII)

This allows the system to detect both obvious structured PII and information that requires nuanced contextual understanding.

### 📊 Privacy Intelligence
* 🔢 **Privacy risk score** (0–100 scale)
* 🚦 **Risk level classification** (LOW, MEDIUM, HIGH, CRITICAL)
* 🧾 **Executive detection summary**
* 💡 **Contextual explanations** for every detected entity
* 🎯 **Recommended protection actions**
* 🔗 **Entity merging and deduplication**

### 🛡️ Privacy Protection
Choose between three protection modes:
* 🔴 **REDACT** — completely remove sensitive values (`[REDACTED: EMAIL]`, `[REDACTED: PAN]`)
* 🎭 **MASK** — hide sensitive portions while preserving structural context (`a***@example.com`, `******3210`)
* 🕵️ **ANONYMIZE** — replace sensitive information with realistic, synthetic surrogate identifiers (`user1@privacylens.internal`, `Alex Morgan`)

### ⬇️ Protected Documents
After applying protection, users can download the sanitized document directly in its native format (.pdf, .docx, .txt).

### 🔐 Privacy-First Design
* **Zero Client Exposure:** Gemini API key stays strictly on the backend.
* **No Secret Logging:** Sensitive document values are never logged or exposed in traces.
* **Stateless & Temporary:** Documents are processed in-memory without persistent database storage.
* **Resilient Fallback:** Gemini API timeouts or failures safely fall back to local rule-based detections.

---

# 🧠 How PrivacyLens Works

PrivacyLens follows a multi-stage privacy processing pipeline:

```text
               👤 USER
                  │
                  ▼
         ┌─────────────────┐
         │   📄 Upload     │
         │    Document     │
         └────────┬────────┘
                  │
                  ▼
         ┌─────────────────┐
         │  ⚛️ Next.js UI  │
         └────────┬────────┘
                  │
                  ▼
         ┌─────────────────┐
         │ ⚙️ FastAPI API   │
         └────────┬────────┘
                  │
                  ▼
         ┌─────────────────┐
         │   📑 Document   │
         │     Parser      │
         │ (PDF/DOCX/TXT)  │
         └────────┬────────┘
                  │
          ┌───────┴───────┐
          │               │
          ▼               ▼
   ┌────────────┐  ┌───────────────┐
   │  ⚡ Local   │  │   🧠 Gemini   │
   │ Detection  │  │  Contextual   │
   │(Regex/Rule)│  │   Detection   │
   └──────┬─────┘  └───────┬───────┘
          │                │
          └───────┬────────┘
                  │
                  ▼
         ┌─────────────────┐
         │ 🔗 Entity Merge │
         │ & Deduplication │
         └────────┬────────┘
                  │
                  ▼
         ┌─────────────────┐
         │ 📊 Privacy Risk │
         │      Score      │
         └────────┬────────┘
                  │
                  ▼
         ┌─────────────────┐
         │ 🛡️ Protection   │
         │ (Redact / Mask /│
         │   Anonymize)    │
         └────────┬────────┘
                  │
                  ▼
         ┌─────────────────┐
         │  ⬇️ Protected   │
         │    Document     │
         └─────────────────┘
```

---

## 🔎 PII Detection Layers

### ⚡ Local Detection
PrivacyLens first performs deterministic local detection for structured, standard sensitive patterns:
* 📧 Email addresses
* 📱 Phone numbers
* 🪪 Indian Aadhaar numbers (12-digit UIDs)
* 🪪 Indian PAN numbers (10-digit tax IDs)
* 💳 Financial identifiers & Credit card numbers
* 🔑 Passwords and credentials
* 🔐 API keys and access tokens

This provides a fast and reliable baseline before running contextual analysis.

### 🧠 Gemini Contextual Detection
Google Gemini is used for context-aware detection of information that cannot be reliably identified through patterns alone:
* 👤 Person names (Patients, clients, employees, witnesses)
* 🏠 Residential and street addresses
* 🏥 Medical conditions, diagnoses, and health data
* 📍 Specific private locations
* 🏢 Identifying organizations
* 🧩 Complex role-dependent or purpose-specific PII

Gemini returns structured information including:
`type`, `value`, `risk`, `reason`, and `recommended_action`.

> **Safe AI Fallback:** If Gemini is unavailable, times out, or quota is exhausted, PrivacyLens safely continues using local detections without crashing.

---

## 🔗 Entity Merging & Deduplication

Both detection layers produce structured entities. PrivacyLens merges the results and resolves overlaps:

```text
  Local Detector                        Gemini AI
  ┌──────────────┐                  ┌──────────────┐
  │ 📧 EMAIL     │                  │ 📧 EMAIL     │
  │ 🪪 PAN       │                  │ 👤 PERSON    │
  └──────┬───────┘                  └──────┬───────┘
         │                                 │
         └───────────────┬─────────────────┘
                         │
                         ▼
             ┌───────────────────────┐
             │ 🔗 Entity Merger       │
             │ (Deduplication &      │
             │  Canonical Resolution)│
             └───────────┬───────────┘
                         │
                         ▼
             ┌───────────────────────┐
             │ • EMAIL  (Source: both│
             │ • PAN    (Source: loc)│
             │ • PERSON (Source: gem)│
             └───────────────────────┘
```

When both systems identify the same entity, PrivacyLens ensures it is represented only once in the final result, preserving the most specific classification and richest reasoning.

---

## 📊 Privacy Risk Scoring

Every detected entity contributes to the document's overall privacy risk calculation:
* 🔢 **Privacy Score (0–100):** Weighted by entity severity (Critical: 30, High: 20, Medium: 10, Low: 5).
* 🚦 **Risk Level:** `LOW` (0–20), `MEDIUM` (21–50), `HIGH` (51–75), `CRITICAL` (76–100).
* 🧾 **Contextual Summary:** Plain-language executive assessment of exposure.
* 💡 **Actionable Reasoning:** Why each piece of information is dangerous to share.

---

## 🛡️ Protection Modes

| Mode | Behavior | Example |
| :--- | :--- | :--- |
| 🔴 **REDACT** | Completely removes the sensitive value and inserts canonical category tokens. | `Email: [REDACTED: EMAIL]`<br>`Phone: [REDACTED: PHONE]`<br>`PAN: [REDACTED: PAN]` |
| 🎭 **MASK** | Obfuscates the sensitive characters while preserving useful structure and formatting. | `Email: a***@example.com`<br>`Phone: ******3210`<br>`PAN: ******234F` |
| 🕵️ **ANONYMIZE** | Replaces sensitive data with realistic, consistent synthetic surrogate placeholders. | `Name: Alex Morgan`<br>`Email: user1@privacylens.internal`<br>`Phone: +1-555-0101` |

---

# 🛠️ Tech Stack

* 🎨 **Frontend:** Next.js 16 (App Router), React 19, TypeScript, Tailwind CSS, Lucide React
* ⚙️ **Backend:** Python 3.10+, FastAPI, Uvicorn, PyMuPDF (fitz), python-docx, Pydantic
* 🧠 **AI / LLM:** Google Gemini API (`gemini-2.5-flash`), official `google-genai` SDK
* ☁️ **Deployment:** ▲ Vercel (Frontend SPA) + 🚀 Render (FastAPI Web Service)

---

# 🏗️ Production Architecture

```text
┌─────────────────────────────────────────────────┐
│                    ▲ Vercel                     │
│               Next.js Frontend                  │
│   https://context-aware-pii-redactor.vercel.app │
└────────────────────────┬────────────────────────┘
                         │
                         │ HTTPS / REST (multipart/json)
                         ▼
┌─────────────────────────────────────────────────┐
│                    🚀 Render                    │
│                 FastAPI Backend                 │
│      https://privacylens-api-tiof.onrender.com  │
└────────────────────────┬────────────────────────┘
                         │
                         │ google-genai SDK
                         ▼
┌─────────────────────────────────────────────────┐
│                🧠 Google Gemini                 │
│          gemini-2.5-flash Contextual AI         │
└─────────────────────────────────────────────────┘
```

---

# 💻 Running Locally

### 📋 Prerequisites
* **Node.js:** 20+
* **Python:** 3.10+
* **Google Gemini API Key:** [Google AI Studio](https://aistudio.google.com/)

---

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/nithin-seb/context-aware-pii-redactor.git
cd context-aware-pii-redactor
```

---

### 2️⃣ Start the Backend

Open a terminal in the project directory:
```bash
cd backend
```

Create and activate a Python virtual environment:

* **Windows:**
  ```powershell
  python -m venv .venv
  .\.venv\Scripts\activate
  ```
* **macOS / Linux:**
  ```bash
  python3 -m venv .venv
  source .venv/bin/activate
  ```

Install dependencies:
```bash
pip install -r requirements.txt
```

Configure backend environment variables in `backend/.env`:
```env
GEMINI_API_KEY=your_gemini_api_key_here
ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
```

Start the FastAPI development server:
```bash
uvicorn main:app --reload --port 8000
```

Verify backend health at: [http://localhost:8000/health](http://localhost:8000/health)
```json
{
  "status": "ok"
}
```

---

### 3️⃣ Start the Frontend

Open a second terminal in the project root:
```bash
npm install
```

Configure frontend environment variables in `.env.local`:
```env
NEXT_PUBLIC_API_URL=http://localhost:8000
```

Start the Next.js development server:
```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

---

# 🔐 Environment Variables

### Backend (`backend/.env` / Render Settings)
| Variable | Required | Description |
| :--- | :--- | :--- |
| `GEMINI_API_KEY` | Recommended | Google Gemini API key for contextual analysis. Kept strictly server-side. |
| `ALLOWED_ORIGINS` | Required | Comma-separated list of allowed frontend origins (e.g. `http://localhost:3000,https://context-aware-pii-redactor.vercel.app`). |
| `PORT` | Optional | Port for Uvicorn (default: `8000`). Automatically set on Render. |
| `GEMINI_MODEL` | Optional | Gemini model name (default: `gemini-2.5-flash`). |

> 🔒 **Security Notice:** `GEMINI_API_KEY` must never be stored in client-side code, `NEXT_PUBLIC_*` variables, or committed to GitHub.

### Frontend (`.env.local` / Vercel Settings)
| Variable | Required | Description |
| :--- | :--- | :--- |
| `NEXT_PUBLIC_API_URL` | Required | Points the Next.js frontend to the FastAPI backend URL (e.g. `http://localhost:8000` or `https://privacylens-api-tiof.onrender.com`). |

---

# 🔌 API Endpoints

### 1. Health Check
* **Method:** `GET /health`
* **Response:**
  ```json
  {
    "status": "ok"
  }
  ```

### 2. Scan Document
* **Method:** `POST /scan`
* **Content-Type:** `multipart/form-data`
* **Parameters:**
  * `file` *(UploadFile, required)*: PDF, DOCX, or TXT file (max 10 MB).
  * `intended_purpose` *(str, optional)*: Context or stated purpose for sharing the document.
* **Response:**
  ```json
  {
    "scan_id": "8d98c926-c990-46d6-8601-9dc5ded6f455",
    "risk_score": 75,
    "risk_level": "HIGH",
    "summary": "Detected 4 sensitive entities across 3 categories. Document assessed with HIGH privacy exposure.",
    "entities": [
      {
        "type": "EMAIL",
        "value": "user@example.com",
        "risk": "HIGH",
        "reason": "Email address enables targeted phishing and identity correlation.",
        "recommended_action": "Mask leaving domain intact",
        "source": "local+gemini"
      }
    ]
  }
  ```

### 3. Protect Document
* **Method:** `POST /protect`
* **Content-Type:** `application/json`
* **Request Body:**
  ```json
  {
    "scan_id": "8d98c926-c990-46d6-8601-9dc5ded6f455",
    "mode": "REDACT"
  }
  ```
* **Supported Modes:** `REDACT` | `MASK` | `ANONYMIZE`
* **Response:** Downloadable sanitized binary file stream with `Content-Disposition` header preserving format (.pdf, .docx, .txt).

---

# 🧪 Testing

The backend includes a test suite covering routes, parser edge cases, scoring weights, and protection modes.

Run tests using pytest:
```bash
cd backend
pytest -v
```

**Test Coverage Highlights:**
* ✅ API Health & CORS preflight checks
* ✅ Multi-format text extraction (PDF, DOCX, TXT)
* ✅ Oversized (10 MB+), empty, and unsupported file rejection
* ✅ Deterministic local regex PII detection
* ✅ Gemini AI contextual detection & structured response validation
* ✅ Graceful AI failure & degraded mode fallback
* ✅ Cross-engine entity merging and deduplication
* ✅ Privacy score calculation & risk level boundaries
* ✅ File sanitization in REDACT, MASK, and ANONYMIZE modes

---

# 📁 Project Structure

```text
context-aware-pii-redactor/
├── 📁 app/
│   ├── globals.css          # Styling & design system tokens
│   ├── layout.tsx           # Next.js root layout & fonts
│   └── page.tsx             # PrivacyLens interactive frontend
├── 📁 backend/
│   ├── main.py              # FastAPI endpoints, CORS, scan cache
│   ├── requirements.txt     # Python direct dependencies
│   ├── .env.example         # Example environment template
│   ├── 📁 services/
│   │   ├── __init__.py
│   │   ├── document_parser.py # PDF/DOCX/TXT text extraction
│   │   ├── local_detector.py  # Regex deterministic PII detection
│   │   ├── gemini.py          # Google Gemini contextual detection
│   │   ├── entity_merger.py   # Deduplication & entity merging
│   │   ├── privacy_score.py   # Severity weights & risk scoring
│   │   └── protection.py      # Redact, Mask, Anonymize transforms
│   └── 📁 tests/
│       ├── test_backend.py    # E2E API & parser test suite
│       └── test_privacy_engine.py # Scoring & protection tests
├── 📁 public/               # Logos, icons, and static assets
├── next.config.ts           # Next.js build configuration
├── package.json             # Frontend dependencies & scripts
├── tsconfig.json            # TypeScript configuration
├── PLAN.md                  # Hackathon project master plan
└── README.md                # Project documentation
```

---

# 🔒 Privacy & Security

PrivacyLens was engineered with privacy by design:
* **API Key Protection:** The Gemini API key remains strictly on the backend and is never accessible to browser clients.
* **Transient In-Memory Cache:** Uploaded document bytes and scan sessions are held only in a short-lived in-memory cache (30-minute TTL) with zero persistent database retention.
* **Zero Sensitive Logging:** The server logs only high-level metadata (file basenames, entity counts, risk levels); raw PII, credentials, and document text are never written to logs.
* **Upload Limits:** Enforces a strict 10 MB limit and blocks malicious or unparsable binary streams.
* **Safe Error Propagation:** Unhandled internal server errors do not leak stack traces or internal environment variables to clients.

---

# ⚠️ Current Limitations

As a hackathon-focused proof of concept, the system intentionally maintains a lightweight footprint:
* 🚫 **No User Authentication:** Sessions are anonymous and ephemeral.
* 🚫 **No Persistent Database:** Scan data expires after TTL or process restart.
* 🚫 **No OCR Engine:** Scanned image-only PDFs without digital text layers are not parsed.
* ⚡ **Single-Instance Assumption:** The in-memory cache requires `/protect` calls to reach the same backend worker as the initial `/scan`.
* 📦 **10 MB File Limit:** Enforced to preserve real-time streaming performance.

---

# 🎯 Why PrivacyLens?

Sharing documents often forces people to manually search for sensitive data before sending them out. That process is:
* ⏳ **Time-consuming:** Manually reviewing pages of text is slow.
* ❌ **Error-prone:** Human reviewers frequently miss hidden PANs, IDs, or credentials.
* 🧠 **Context-dependent:** A person's name or medical condition may be private in one context but normal in another.

PrivacyLens answers three critical questions before sharing:
1. **What sensitive information is present?** (Hybrid rule + AI detection)
2. **How risky is the document?** (Explainable 0–100 privacy scoring)
3. **How can it be shared more safely?** (One-click Redact, Mask, or Anonymize downloads)

---

# 🏆 Hackathon Highlights

* 🔐 **Privacy-First Architecture**
* ⚡ **Hybrid Deterministic + AI Detection Pipeline**
* 🧠 **Context-Aware PII Analysis with Gemini 2.5 Flash**
* 🔗 **Clean Multi-Engine Entity Deduplication**
* 📊 **Calibrated & Explainable Privacy Exposure Scoring**
* 🛡️ **Native File Redaction (PDF, DOCX, TXT)**
* ☁️ **Full Cloud Deployment (Vercel + Render)**

---

## 🌐 Links

* 🚀 **Live Frontend Application:** [https://context-aware-pii-redactor.vercel.app](https://context-aware-pii-redactor.vercel.app)
* ⚙️ **Backend API Service:** [https://privacylens-api-tiof.onrender.com](https://privacylens-api-tiof.onrender.com)
* 💻 **GitHub Repository:** [https://github.com/nithin-seb/context-aware-pii-redactor](https://github.com/nithin-seb/context-aware-pii-redactor)
