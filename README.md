<div align="center">

# 🛡️ OMG — Outbound Mail Gatekeeper

**Enterprise Email Security & Validation Backend**

[![Python](https://img.shields.io/badge/Python-FastAPI-0b7285?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Database](https://img.shields.io/badge/Database-MySQL-0b7285?style=for-the-badge&logo=mysql&logoColor=white)](https://www.mysql.com/)
[![API](https://img.shields.io/badge/API-v3.3.0-364fc7?style=for-the-badge)](#)

*Inspect. Evaluate. Decide. Protect.*

</div>

---

> **📌 Project at a glance**
>
> | **Backend** | **Primary API** | **Database** | **Purpose** |
> |:--|:--|:--|:--|
> | FastAPI / Python | `POST /api/v1/analyze` | MySQL | Validate outbound email content, URLs and optional attachments |



**Backend:** FastAPI / Python  
**Application version in source:** `3.3.0`  
**Primary API:** `POST /api/v1/analyze`  
**Database:** MySQL
**Purpose:** Inspect outbound email content, URLs and optional attachments, then return a policy verdict (`SAFE`, `WARNING` or `RESTRICTED`).

> **⚠️ Important — email delivery is outside OMG's scope**  
> OMG validates email and returns a policy decision; it does **not** send or queue email. The calling mail portal must enforce the backend verdict before it performs its own send/queue operation.

---


---

## 🧭 Documentation contents

| Section | What you'll find |
|:--|:--|
| [1. What OMG does](#-1-what-omg-does) | End-to-end validation workflow |
| [2. Architecture](#-2-architecture-and-request-flow) | Request flow and source-file responsibilities |
| [3. Technology](#-3-technology) | Frameworks, libraries and runtime components |
| [4. Installation](#-4-installation-and-local-execution) | Windows/Linux setup and run commands |
| [5. Configuration](#-5-environment-configuration) | Environment variables and `.env` template |
| [6. Authentication](#-6-authentication-and-account-sessions) | Login, tokens and sessions |
| [7. Main API](#-7-main-email-validation-api) | Request formats and API examples |
| [8. Validators](#-8-how-the-three-validators-work) | Content, URL and attachment inspection |
| [9. Scoring policy](#-9-scoring-and-final-verdict-policy) | Weights, thresholds and verdict precedence |
| [10. MySQL](#-10-mysql-data-storage) | Tables and persistence |
| [11. Operations](#-11-operational-endpoints) | Health, readiness and status endpoints |
| [12. Frontend](#-12-frontend--demo-portal) | Portal responsibilities |
| [13. Deployment](#-13-deployment-checklist) | Production-readiness checklist |
| [14. Troubleshooting](#-14-troubleshooting) | Common failures and checks |
| [15. Security](#-15-security-notes-and-limitations) | Important safeguards and limitations |
| [16. Repository hygiene](#-16-repository-hygiene) | Git exclusions and secret handling |
| [17. Quick start](#-17-quick-start-summary) | Condensed startup instructions |

---


---

## 🎯 1. What OMG does

OMG provides a single validation workflow for an email:

1. Receives the email subject and body and, optionally, HTML and uploaded files.
2. Inspects text/HTML for suspicious, fraudulent, harmful or policy-violating content.
3. Extracts and structurally checks URLs found in the email.
4. Validates uploaded attachments, including file structure, type, hash, archive limits, antivirus status and extractable document text.
5. Converts the reports from the three inspection modules into common findings and module scores.
6. Applies the central decision policy in `decision_making.py` and `score_policy.py`.
7. Returns a consolidated result, including the verdict, scores, reasons, and whether sending is allowed or acknowledgement is required.
8. Saves the result against the authenticated user's account in MySQL.

The three independent inspection areas are:

| Module | Main responsibility |
|---|---|
| Content | Subject, plain text, HTML, fraud/contextual rules and optional ML classification |
| URL | Structural inspection of HTTP(S) and embedded/bare web links |
| Attachments | File validation, malware scanning when configured, document-content inspection and OCR |

**Decision authority:** The backend produces the verdict. The frontend should display the result; it must not independently decide that an email is safe.


---

## 🏗️ 2. Architecture and request flow

```text
Mail Portal / Client
        |
        | HTTPS + Bearer access token
        v
FastAPI application (app.py)
        |
        +--> Authentication (auth.py / security.py)
        |
        +--> Content validator (Content/)
        |
        +--> URL validator (URL/)
        |
        +--> Attachment gate (Attachments/)
        |
        v
Decision engine (decision_making.py)
        |
        +--> score_policy.py
        +--> pattern_scoring.py
        |
        v
Consolidated API response
        |
        +--> MySQL persistence (database.py / db_repository.py)
        |
        v
Frontend displays SAFE / WARNING / RESTRICTED
```

### Main source files

| File / folder | Responsibility |
|---|---|
| `app.py` | FastAPI application, lifespan checks, health/readiness routes, `/api/v1/analyze`, response assembly and history JSON view |
| `auth.py` | Register, login, profile and logout actions; Bearer-token user dependency |
| `security.py` | Password hashing, JWT creation/decoding and session identifier hashing |
| `database.py` | MySQL engine, relational models and schema initialization |
| `db_repository.py` | Persist analysis results and retrieve account-specific history |
| `decision_making.py` | Authoritative combined verdict and investigation precedence |
| `score_policy.py` | Weights, score thresholds, severity risk points and score projection settings |
| `pattern_scoring.py` | Common finding/module data structures and confidence-adjusted risk calculations |
| `hybrid_scoring.py` | Deprecated compatibility layer that delegates verdict evaluation to `decision_making.py` |
| `Content/` | Email text, HTML, contextual and fraud-pattern validation |
| `URL/` | URL extraction and structural URL validation |
| `Attachments/` | Upload checks, malware scanner integration, content extraction, OCR and attachment warning acknowledgement |
| `frontend/index.html` | Browser-based portal/demo UI |
| `requirements.txt` | Python runtime dependencies |


---

## 🧰 3. Technology

### Python backend

- **FastAPI** — HTTP API and request handling.
- **Uvicorn** — ASGI server.
- **Pydantic** — request validation and typed data handling.
- **BeautifulSoup** — HTML parsing and link/text inspection.
- **idna** — internationalized domain-name handling.
- **PyMuPDF (`pymupdf`) and pypdf** — PDF parsing and inspection.
- **Pillow** — image decoding and image safety checks.
- **pytesseract** — Python integration with the Tesseract OCR executable.
- **defusedxml** — safer XML parsing for office document inspection.
- **SQLAlchemy / PyMySQL** — MySQL persistence.
- **PyJWT** — signed access tokens.
- **pwdlib[bcrypt]** — password hashing.
- **scikit-learn, NumPy and joblib** — ML model support.
- **python-multipart** — multipart file upload parsing.
- **python-dotenv** — environment configuration.

The exact dependency ranges are maintained in `requirements.txt`. Install from that file rather than manually installing a different set of package versions.


---

## ⚙️ 4. Installation and local execution

### Prerequisites

Install or arrange the following before starting the backend:

1. Python compatible with the installed dependencies.
2. MySQL server reachable at the configured host and port. The configured user must be allowed to create the database and tables on first startup.
3. Tesseract OCR executable if OCR is to be used. Installing `pytesseract` alone does not install Tesseract itself.
4. ClamAV daemon (`clamd`) if mandatory antivirus scanning is enabled.
5. The project's model and rule files if ML/production settings require them.

### Windows — Command Prompt

Open a terminal in the project root (the directory containing `app.py` and `requirements.txt`).

```bat
cd path\to\Outbound-Mail-Validator

python -m venv .venv
.venv\Scripts\activate

python -m pip install --upgrade pip
pip install -r requirements.txt
```

Create a local `.env` file using the configuration section below. Do not copy a real production `.env` into source control or share it in a ZIP.

Start the API:

```bat
uvicorn app:app --host 127.0.0.1 --port 8000 --reload
```

Open the portal:

- `http://127.0.0.1:8000/`
- `http://127.0.0.1:8000/portal`

In development, FastAPI documentation is available at:

- `http://127.0.0.1:8000/docs`
- `http://127.0.0.1:8000/redoc`

The source disables the documentation and OpenAPI routes when `settings.is_production` is true.

### Linux

```bash
cd /path/to/Outbound-Mail-Validator

python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
pip install -r requirements.txt

uvicorn app:app --host 0.0.0.0 --port 8000
```

For a production process, run behind a reverse proxy/load balancer with HTTPS, appropriate process supervision, resource limits and restricted network access. Do not expose a development `--reload` server to the public internet.


---

## 🔐 5. Environment configuration

The application reads configuration from `.env` and/or process environment variables. The following names are referenced by the supplied source. Not every variable is mandatory in every environment; defaults and production checks are described below.

### Core application and database

| Variable | Purpose |
|---|---|
| `MYSQL_HOST` | MySQL hostname. Default: `localhost`. |
| `MYSQL_PORT` | MySQL port. Default: `3306`. |
| `MYSQL_USER` | MySQL username. Default: `root`. |
| `MYSQL_PASSWORD` | MySQL password. Required by `database.py`; keep it in an ignored local env file or deployment secrets. |
| `MYSQL_DATABASE` | Database name. Default: `OMG_Database`; created on startup when absent. |
| `OMG_API_PREFIX` | API prefix. Source default: `/api/v1`. |
| `OMG_ENV` | Environment selector; `production`/`prod` activates production behaviour. |
| `OMG_ENVIRONMENT` | Environment selector used by `Content/config.py`; defaults from `OMG_ENV` or `development`. |
| `OMG_LOG_LEVEL` | Logging level; source default: `INFO`. |
| `OMG_MAX_REQUEST_BYTES` | Request-size configuration; source default: `65000000`. |

### Authentication

| Variable | Purpose |
|---|---|
| `OMG_JWT_SECRET` | Secret used to sign access tokens. Source requires at least 32 characters. Use a long random secret. |
| `OMG_JWT_ALGORITHM` | JWT signing algorithm; source default: `HS256`. |
| `OMG_ACCESS_TOKEN_EXPIRE_MINUTES` | Access-token lifetime in minutes; source default: `60`. |

The `security.py` implementation uses `OMG_ACCESS_TOKEN_EXPIRE_MINUTES`. Older/alternate names such as `OMG_JWT_EXPIRE_MINUTES` should not be assumed to affect the current implementation unless the code is changed.

### Content rules and ML

| Variable | Purpose |
|---|---|
| `OMG_RULES_PATH` | Runtime content rules file; default `Content/data/omg_rules.json`. |
| `OMG_MODEL_PATH` | Content classifier artifact; default `Content/models/email_classifier.joblib`. |
| `OMG_ENABLE_ML` | Enables the optional content ML classifier. |
| `OMG_REQUIRE_ML` | Makes the content ML classifier mandatory; production validation requires this to be enabled. |
| `OMG_ML_MIN_CONFIDENCE` | Minimum ML confidence setting; source default `0.60`; production validation requires 0.50–0.99. |
| `OMG_ENABLE_EXPERIMENTAL_TFIDF` | Enables experimental TF-IDF functionality. |
| `OMG_TRUSTED_LINK_DOMAINS` | Trusted-domain configuration referenced by URL/content logic. |

The source comments explicitly distinguish model confidence from a calibrated security safety score. ML output should be treated as one input to the overall inspection, not as proof that an email is safe.

### Attachment and antivirus settings

| Variable | Purpose |
|---|---|
| `OMG_REQUIRE_CLAMAV` | Whether ClamAV scanning is mandatory. |
| `OMG_CLAMAV_HOST` | `clamd` host; source default `127.0.0.1`. |
| `OMG_CLAMAV_PORT` | `clamd` TCP port; source default `3310`. |
| `OMG_CLAMAV_TIMEOUT` | Scanner connection/read timeout; source default `6.0` seconds. |
| `OMG_MAX_FILES` | Maximum attachment count. |
| `OMG_MAX_FILE_MB` | Maximum size per attachment in MB. |
| `OMG_MAX_TOTAL_MB` | Maximum combined attachment size in MB. |
| `OMG_DENIED_HASHES_FILE` | Optional text file containing one denied SHA-256 hash per line. |
| `OMG_ML_MODE` | Optional attachment ML mode. |
| `OMG_ML_MODEL_PATH` | Attachment ML artifact path. |
| `OMG_ML_THRESHOLD` | Attachment ML threshold. |

The attachment policy code defines limits for archive entry count, expanded archive size, compression ratio, archive depth and PDF page count as well. The effective values are set in `Attachments/attachments.py` and can be adjusted there or through the environment variables read by that file.

The attachment gate also applies portal-level defaults in code when the corresponding variables have not already been set: 5 files, 3 MB per file and 10 MB total. Check the effective configuration in the deployed process rather than assuming a value from a different environment.

### Attachment content inspection and OCR

| Variable | Purpose |
|---|---|
| `OMG_CONTENT_ENABLED` | Enables attachment content inspection. |
| `OMG_CONTENT_LURE_RULES` | Enables attachment lure-pattern rules. |
| `OMG_CONTENT_OCR_MODE` | OCR mode: `off`, `when_needed` or `all`. |
| `OMG_CONTENT_OCR_REQUIRED` | Makes OCR mandatory. |
| `OMG_CONTENT_IMAGE_POLICY` | Image policy: `ocr_only` or `restrict`. |
| `OMG_CONTENT_OCR_LANGUAGE` | Tesseract language; source default `eng`. |
| `OMG_TESSERACT_CMD` | Optional explicit path to `tesseract.exe`/Tesseract executable. |
| `OMG_CONTENT_ML_MODE` | Optional attachment text-content ML mode. |
| `OMG_CONTENT_ML_MODEL_PATH` | Attachment text-content ML artifact. |
| `OMG_CONTENT_ML_THRESHOLD` | Attachment text-content ML threshold. |

The attachment content scanner documents its limitations: OCR extracts text from images/scanned documents; OCR is not a complete visual moderation system. The code can restrict visual media when a suitable reviewed vision model is not integrated.

### Warning acknowledgement

| Variable | Purpose |
|---|---|
| `OMG_WARNING_SIGNING_KEY` | HMAC signing key used for attachment warning challenge/acknowledgement tokens. Production code requires at least 32 bytes. |

Do not expose this key in frontend JavaScript. The warning token is bound to the attachment set and expires after 10 minutes in the current implementation.

### Example `.env` template

Use this as a starting template only. Replace placeholders with your own values and tune optional settings for the target environment.

```dotenv
MYSQL_HOST=localhost
MYSQL_PORT=3306
MYSQL_USER=root
MYSQL_PASSWORD=<your-mysql-password>
MYSQL_DATABASE=OMG_Database

OMG_API_PREFIX=/api/v1
OMG_ENV=development
OMG_ENVIRONMENT=development
OMG_LOG_LEVEL=INFO
OMG_MAX_REQUEST_BYTES=65000000

OMG_JWT_SECRET=<generate-a-random-secret-at-least-32-characters>
OMG_JWT_ALGORITHM=HS256
OMG_ACCESS_TOKEN_EXPIRE_MINUTES=60

OMG_RULES_PATH=Content/data/omg_rules.json
OMG_MODEL_PATH=Content/models/email_classifier.joblib
OMG_ENABLE_ML=false
OMG_REQUIRE_ML=false
OMG_ML_MIN_CONFIDENCE=0.60
OMG_ENABLE_EXPERIMENTAL_TFIDF=false

OMG_REQUIRE_CLAMAV=false
OMG_CLAMAV_HOST=127.0.0.1
OMG_CLAMAV_PORT=3310
OMG_CLAMAV_TIMEOUT=6.0
OMG_MAX_FILES=5
OMG_MAX_FILE_MB=3
OMG_MAX_TOTAL_MB=10
OMG_DENIED_HASHES_FILE=Attachments/security/denied_hashes.txt

OMG_CONTENT_ENABLED=true
OMG_CONTENT_LURE_RULES=true
OMG_CONTENT_OCR_MODE=when_needed
OMG_CONTENT_OCR_REQUIRED=false
OMG_CONTENT_IMAGE_POLICY=ocr_only
OMG_CONTENT_OCR_LANGUAGE=eng

OMG_WARNING_SIGNING_KEY=<generate-a-different-random-secret-at-least-32-bytes>
```

Do not use the sample URI or placeholders as real credentials. Keep secrets in the deployment platform's secret manager/environment configuration.


---

## 👤 6. Authentication and account sessions

The consolidated authorization route is:

`POST /api/v1/authorization`

It accepts an `action` field with one of the supported values:

- `register`
- `login`
- `profile`
- `logout`

The request model also defines optional `name`, `email` and `password` fields. Which fields are required depends on the selected action.

After login, the client uses the returned access token in the HTTP header:

```http
Authorization: Bearer <access_token>
```

The `get_current_user` dependency validates the JWT, checks the active MySQL session and confirms that the user account is active. The analysis endpoint requires this authenticated user dependency.

Password values must never be stored or logged in plaintext. The current security module uses `pwdlib`'s recommended password hashing interface. Session identifiers are hashed before being stored in MySQL.


---

## 🔌 7. Main email validation API

### `POST /api/v1/analyze`

This is the single business endpoint for the combined email validation flow. It requires a valid Bearer access token.

Supported request content types:

- `application/json`
- `multipart/form-data`
- `application/x-www-form-urlencoded` is also accepted by the current handler.

The endpoint processes the email, adds the authenticated account details, saves the result in MySQL and returns the consolidated result. If validation succeeds but MySQL persistence fails, the handler returns HTTP `503` rather than reporting a successful saved analysis.

### JSON request example

```http
POST /api/v1/analyze
Authorization: Bearer <access_token>
Content-Type: application/json
```

```json
{
  "channel": "email",
  "subject": "Project meeting",
  "body": "Hello team, our project meeting is scheduled for Monday at 10 AM.",
  "html": "<p>Hello team, our project meeting is scheduled for Monday at 10 AM.</p>",
  "recipients": [
    "recipient@example.com"
  ]
}
```

The `EmailRequest` schema requires a non-empty `subject` and at least one non-empty `body` or `html` value. The body and HTML fields have maximum lengths of 1,000,000 characters each. Recipient addresses are validated. The schema has `extra='forbid'`, so unsupported JSON fields are rejected.

### Multipart request

Use multipart when uploading files. The request contains the email fields plus one or more file parts. The precise field names and upload parsing rules are defined in `_multipart_payload()` and `_ANALYZE_REQUEST_BODY` inside `app.py`; keep the client field names aligned with that implementation.

Example using `curl` (adjust the field names to match the multipart schema exposed by the current `app.py`):

```bash
curl -X POST "http://127.0.0.1:8000/api/v1/analyze" \
  -H "Authorization: Bearer <access_token>" \
  -F "subject=Quarterly report" \
  -F "body=Please review the attached report." \
  -F "files=@report.pdf"
```

For multipart requests, do **not** manually set the `Content-Type` header in a browser `fetch` call. Let the browser generate the multipart boundary. A mismatched boundary can cause malformed multipart errors.

### Request ID

The endpoint reads an optional `x-request-id` header and stores it with the analysis record. Use a unique request ID from the calling application when request-level tracing or duplicate correlation is required.


---

## 🔍 8. How the three validators work

### 8.1 Content inspection — `Content/`

Relevant files include:

- `content_validator.py`
- `rule_checks.py`
- `contextual_risk.py`
- `fraud_detection.py`
- `html_inspection.py`
- `classifier.py`
- `model_loader.py`
- `pattern_catalog.py`
- `data/omg_rules.json`
- `data/omg_pattern_catalog.json`
- `models/email_classifier.joblib`

The content validator inspects subject, body and HTML. It combines rule-based checks, contextual/fraud-pattern inspection and HTML inspection. The optional ML classifier is controlled by the ML settings. Coverage metadata records whether the ML stage was disabled, completed or unavailable.

The classifier's confidence is not itself a calibrated safety probability. The decision engine uses findings, severity, confirmation, confidence and inspection completeness when making the final decision.

### 8.2 URL inspection — `URL/`

Main file: `URL/url_validator.py`.

The URL module extracts explicit HTTP(S) and bare `www.` links from email text and performs structural checks. The source documents that it does not browse destinations, resolve external reputation or claim that a URL is malicious/safe based on live website content.

The code distinguishes ordinary in-page anchors, relative paths and benign schemes such as `mailto:`/`tel:` from network destinations. It identifies dangerous active-content schemes such as `javascript:`, `data:` and `vbscript:`. It also assigns severities to findings such as malformed URLs, invalid hostnames, insecure login URLs, IP-address links, credentials in URLs, visible-link mismatches, internationalized hostnames and shortened URLs.

> **⚠️ URL inspection limitation**  
> Structural validation is not a substitute for live threat-intelligence/reputation checks, safe browsing, redirect-chain analysis or sandboxing. Do not describe the URL module as doing those things unless they are separately implemented.

### 8.3 Attachment inspection — `Attachments/`

Relevant files include:

- `attachments.py` — file validation, hashing, file signatures, archive checks and ClamAV communication.
- `attachment_gate.py` — shared attachment policy gate and result normalization.
- `content_validator.py` — text extraction, contextual checks and OCR.
- `attachment_ml.py` — optional attachment ML detector.
- `text_content_ml.py` — optional ML support for extracted text.
- `content_risk_rules.py` and `warning_rules.py` — attachment-content and warning rules.
- `warning_ack.py` — signed warning challenge/acknowledgement tokens.
- `security/denied_hashes.txt` — optional SHA-256 denylist file.

The attachment validator checks supported extensions, rejects dangerous executable/script/macro-enabled suffixes, checks file signatures where applicable, parses supported formats, calculates SHA-256 hashes and checks the optional denylist. ZIP/archive inspection has limits intended to reduce archive traversal and decompression-bomb risk.

The attachment code's allowlist includes PDF, TXT, CSV, JSON, PNG, JPG/JPEG, GIF, DOCX, XLSX, PPTX and ZIP. The attachment gate additionally defines portal-level limits and an allowed extension set. Verify the actual runtime policy before changing the portal's upload hint.

#### ClamAV operation

The implementation communicates with a ClamAV `clamd` service using the INSTREAM protocol over TCP. It does not simply install or run an antivirus engine because the Python dependency is present. A reachable and correctly configured `clamd` daemon is required.

- Host is configured with `OMG_CLAMAV_HOST`.
- Port is configured with `OMG_CLAMAV_PORT` (source default `3310`).
- Timeout is configured with `OMG_CLAMAV_TIMEOUT`.
- `OMG_REQUIRE_CLAMAV=true` makes the scan mandatory.
- If scanning is not required, the report can explicitly state that malware scanning was disabled. A SAFE result in that mode must not be represented as proof that the file is malware-free.
- Production lifespan checks require ClamAV to be configured as mandatory.

For deployment, install ClamAV on the host/container or use a separately managed scanner service reachable over a private network. Keep the daemon off the public internet. Update virus definitions and monitor scanner health. Test both a clean test file and the standard EICAR antivirus test file in a controlled environment before release.

#### OCR and document content

`pytesseract` is only a Python wrapper. Install the native Tesseract executable and ensure the process can locate it. On Windows, `OMG_TESSERACT_CMD` can point to the executable. Scanned PDF OCR also uses PyMuPDF and may need the Tesseract language data configured in the runtime.

OCR and document parsing are bounded by limits such as page count, text length, image pixels and archive expansion. If required inspection is unavailable or incomplete, the decision engine is designed to fail closed rather than silently treating the scan as complete.


---

## ⚖️ 9. Scoring and final verdict policy

The authoritative scoring configuration is in `score_policy.py`; the verdict precedence is implemented in `decision_making.py`. Keep documentation and client-side display aligned with these source files.

### 9.1 Module weights

The weighted policy score uses these configured weights:

| Module | Weight |
|---|---:|
| Content | 0.40 (40%) |
| URL | 0.30 (30%) |
| Attachments | 0.30 (30%) |
| **Total** | **1.00 (100%)** |

The weighted score is:

\[
S_w = 0.40S_c + 0.30S_u + 0.30S_a
\]

where `S_c`, `S_u` and `S_a` are the content, URL and attachment safety scores respectively, each on a 0–100 scale.

### 9.2 Finding severity and risk points

`score_policy.py` defines risk points by severity:

| Severity | Risk points |
|---|---:|
| INFO | 0 |
| LOW | 12 |
| MEDIUM | 22 |
| HIGH | 45 |
| CRITICAL | 60 |

For an unconfirmed finding, the risk contribution is multiplied by its detector confidence. Confirmed findings use the full risk-point value. `pattern_scoring.py` collapses duplicate finding names to their strongest risk contribution when calculating its risk total, avoiding duplicate counting of the same named finding.

The module safety score also uses severity penalties defined in `pattern_scoring.py`:

| Severity | Module score penalty |
|---|---:|
| INFO | 0 |
| LOW | 5 |
| MEDIUM | 15 |
| HIGH | 35 |
| CRITICAL | 60 |

Unconfirmed findings have their penalty multiplied by confidence. The resulting module score is bounded between 0 and 100.

### 9.3 Score bands

The current source configuration is:

| Score | Verdict |
|---:|---|
| 0.00–74.99 | ⛔ `RESTRICTED` |
| 75.00–84.99 | ⚠️ `WARNING` |
| 85.00–100.00 | ✅ `SAFE` |

The configured constants are `WARNING_THRESHOLD = 75.0` and `SAFE_THRESHOLD = 85.0`. The score projection logic keeps reported scores inside the band belonging to the verdict.

### 9.4 Verdict precedence — verdict first, score second

The code does not rely only on a weighted average. It evaluates mandatory policy conditions and blocking findings first. The documented precedence in `decision_making.py` is:

1. Any mandatory inspection incomplete → `RESTRICTED`.
2. Any confirmed `HIGH`/`CRITICAL` finding → `RESTRICTED`.
3. Investigation status `UNRESOLVED` → `RESTRICTED`.
4. Lowest module score below 75 and investigation not cleared → `RESTRICTED`.
5. Investigation status `PENDING` → `WARNING`.
6. Lowest module score below 85 → `WARNING` and investigation required.
7. Otherwise, use the weighted policy score to decide the final band.

This order is important. A weighted average can hide a serious problem in one module. For example, a very high content score could mathematically offset a low URL or attachment score. The verdict-first rules prevent a confirmed critical issue or incomplete mandatory inspection from being averaged away by other good scores.

The source also defines hard-block finding codes for threat-related findings. Those are treated as confirmed blocking conditions by the decision engine.

### 9.5 Worst-anchored aggregate risk

The central policy also defines:

- `OVERALL_CORROBORATION_FACTOR = 0.25`
- `OVERALL_EXTRA_MODULE_RISK = 2.5`

In the overall risk aggregation, the worst module anchors the risk. Other flagged modules contribute at the reduced corroboration factor, and each additional module below the SAFE threshold adds a fixed corroboration risk. In conceptual form:

\[
R_{\text{overall}} =
R_{\max}
+ 0.25 \sum R_{\text{other}}
+ 2.5(k-1)
\]

where `R_max` is the largest module risk, `R_other` are the remaining module risks, and `k` is the number of modules counted as below the SAFE threshold by the implementation.

> **💡 Policy interpretation**  
> `0.25` lets secondary-module evidence contribute without allowing it to dominate the worst module. `2.5` adds a small fixed amount when multiple independent modules are flagged. These are configurable policy parameters—not universal scientific constants—and should be tuned against labelled legitimate and malicious email data.

The implementation uses these constants within its overall-risk calculation and then projects the result into the score range corresponding to the already-selected verdict. Do not treat this risk formula as the only verdict rule.

### 9.6 Investigation and acknowledgement

The engine defines investigation states:

- `NOT_REQUIRED`
- `PENDING`
- `CLEARED`
- `UNRESOLVED`

A lower-scoring module may trigger an investigation requirement. Pending investigation produces WARNING; unresolved investigation produces RESTRICTED. A cleared investigation can affect the restriction path as implemented in `decision_making.py`.

The attachment warning challenge is a separate acknowledgement mechanism bound to the exact attachment names, order, sizes and SHA-256 digests. It expires after 10 minutes. The source comments caution that the local token mechanism alone cannot prove a human read the warning; production integration should record authenticated, auditable consent.


---

## 🗄️ 10. MySQL data storage

`database.py` reads these variables from `n-omg.env` or the process environment:

- `MYSQL_HOST` (default `localhost`)
- `MYSQL_PORT` (default `3306`)
- `MYSQL_USER` (default `root`)
- `MYSQL_PASSWORD` (required)
- `MYSQL_DATABASE` (default `OMG_Database`)

At startup it verifies the MySQL connection, creates the database if needed, and creates the tables and indexes:

- `users`: unique email and hashed password.
- `auth_sessions`: unique hashed JWT session token, revocation state and expiry.
- `email_analysis`: JSON email/module data, verdict fields and account history.

Expired sessions are rejected during authentication; MySQL does not automatically delete them. The tables used are:

| Table | Purpose |
|---|---|
| `users` | User accounts |
| `auth_sessions` | Active/revoked access-token sessions and expiry |
| `email_analysis` | Persisted email analysis results |

`db_repository.py` stores the authenticated account ID, user email, request ID, selected email fields, final status, confidence score, send/acknowledgement flags, score contributions, module reports, errors and UTC creation timestamp.

History retrieval in `db_repository.py` is scoped to the authenticated account ID. The consolidated `app.py` also contains a JSON view endpoint; review its access-control requirements before exposing that endpoint in a production environment.


---

## 📡 11. Operational endpoints

The following routes are present in `app.py`:

| Method | Route | Purpose |
|---|---|---|
| GET | `/` | Serves `frontend/index.html` |
| GET | `/portal` | Serves the portal page |
| GET | `/health` | Basic service-running response |
| GET | `/api/v1/health` | Basic service-running response under API prefix |
| GET | `/ready` | Readiness summary |
| GET | `/api/v1/ready` | Readiness summary under API prefix |
| GET | `/status` | Authenticated service status |
| GET | `/api/v1/status` | Authenticated service status under API prefix |
| POST | `/api/v1/authorization` | Register/login/profile/logout action |
| POST | `/api/v1/analyze` | Main email analysis endpoint |
| GET | `/api/v1/json_view` | JSON view/history-related endpoint |

The prefix is configurable using `OMG_API_PREFIX`; the table shows the default `/api/v1`.

`/health` only reports that the application process is running. `/ready` checks the presence of required rules/model artifacts according to configuration and explicitly notes that antivirus/OCR readiness needs separate runtime checks. A successful health response does not prove that MySQL, ClamAV or OCR are all operational.


---

## 🖥️ 12. Frontend / demo portal

The repository includes `frontend/index.html`, served by FastAPI at `/` and `/portal`. It is a browser-facing demo/portal for submitting email data, optionally adding attachments, and presenting the backend's validation outcome. The frontend should send the authenticated Bearer token and use the exact request field names expected by `/api/v1/analyze`. It should display the backend verdict, findings, module scores and warning/restricted popup state, and should only enable the mail application's send flow when the backend response permits it and any required acknowledgement has been recorded. The frontend is a presentation and integration layer: it is not the source of truth for scoring and it does not replace the backend's security checks. **The OMG backend itself does not send the email.**


---

## 🚀 13. Deployment checklist

### Before deployment

-  Use a clean source checkout; do not deploy a developer's `.venv` directory.
-  Remove `.env`, credentials, tokens and other secrets from the deployment artifact and repository history.
-  Confirm that `requirements.txt` installs successfully in the target runtime.
-  Configure `MYSQL_HOST`, `MYSQL_PORT`, `MYSQL_USER`, `MYSQL_PASSWORD` and `MYSQL_DATABASE` in the deployment environment.
-  Set a unique, strong `OMG_JWT_SECRET` (at least 32 characters).
-  Set a separate strong `OMG_WARNING_SIGNING_KEY` (at least 32 bytes).
-  Set `OMG_ENV=production` and `OMG_ENVIRONMENT=production`.
-  Confirm the configured rules file and classifier model artifact exist at the resolved paths.
-  Production source validation requires `OMG_REQUIRE_ML=true` and a valid model file.
-  Production attachment gate requires `OMG_REQUIRE_CLAMAV=true`.
-  Configure a reachable private ClamAV `clamd` service and verify its health/definitions.
-  Install Tesseract and required language data; test OCR using a scanned PDF and image.
-  Set production OCR and visual-media policy deliberately; the source attachment gate has additional production requirements.
-  Verify file-size, request-size, archive and page limits against the host's memory/storage capacity.
-  Use HTTPS and restrict CORS/origin access at the application or gateway layer.
-  Ensure frontend code does not contain MySQL credentials, JWT signing secrets, warning signing keys or other server secrets.
-  Test register/login/logout, invalid/expired tokens, JSON requests, multipart requests and each verdict.
-  Test database persistence and account-isolated history.
-  Test scanner-unavailable behaviour; mandatory scanner failure must not be reported as a clean scan.
-  Monitor logs, API latency, exceptions, MySQL connectivity, disk usage and scanner health.

### Uvicorn deployment command

For a platform that provides a `PORT` environment variable:

```bash
uvicorn app:app --host 0.0.0.0 --port $PORT
```

For a fixed port:

```bash
uvicorn app:app --host 0.0.0.0 --port 8000
```

Do not use `--reload` in production.

### External services

The application requires MySQL. ClamAV and Tesseract are external runtime components, not Python packages installed by `pip install -r requirements.txt`. Ensure the deployed application can reach them and that their executables/daemons/data are installed in the runtime image or on a private service.


---

## 🛠️ 14. Troubleshooting

| Symptom | Checks |
|---|---|
| MySQL connection error at startup | Verify `MYSQL_HOST`, `MYSQL_PORT`, `MYSQL_USER`, `MYSQL_PASSWORD`, MySQL availability, and database-creation permissions. |
| `OMG_JWT_SECRET` startup error | Set a secret of at least 32 characters and restart the application. |
| HTTP 401 on protected routes | Send `Authorization: Bearer <access_token>`; verify token expiry, JWT secret consistency, active MySQL session and logout/revocation state. |
| HTTP 422 request validation error | Check required subject/body-or-html fields, allowed JSON keys, recipient format and multipart field names. |
| HTTP 400 malformed multipart | Let the client/browser create the multipart boundary; do not manually set a conflicting `Content-Type` boundary. |
| HTTP 413 / request too large | Check `OMG_MAX_REQUEST_BYTES`, per-file size, total attachment size and reverse-proxy upload limits. |
| ClamAV unavailable / scanner error | Check that `clamd` is running, reachable from the app container, listening on the configured host/port and accepting INSTREAM requests. |
| OCR unavailable | Install the native Tesseract executable and language data; configure `OMG_TESSERACT_CMD` if it is not on PATH. |
| Required ML artifact missing | Verify `OMG_MODEL_PATH` and `OMG_RULES_PATH` relative to the project root and ensure the files are included in the deployment artifact. |
| Application starts locally but fails in production | Review production-only checks: required ML, model/rules files, mandatory ClamAV and attachment content/OCR policy. |
| Validation succeeds but API returns 503 | The current analyze handler saves the result before returning; inspect MySQL connectivity, tables and logs for persistence failure. |
| SAFE attachment result includes malware-scan-disabled warning | ClamAV is not required/enabled in that environment. Do not interpret that result as proof of malware absence. |


---

## 🔒 15. Security notes and limitations

1. **No email delivery:** OMG validates and returns a decision. The mail system must enforce the decision before sending.
2. **Authentication:** Protect analysis and account/history routes with authenticated user identity. Never trust an account ID supplied by an untrusted browser request.
3. **Secrets:** Never commit `.env`, JWT secrets, MySQL credentials or HMAC signing keys. Rotate any secret that has been shared or committed.
4. **Uploads:** Keep uploaded data in memory or controlled temporary storage, apply size/type limits, do not execute uploaded files and clean up temporary files.
5. **Antivirus:** A Python socket client is not an antivirus engine. A functioning ClamAV daemon and updated definitions are required for actual malware scanning.
6. **OCR:** OCR detects text; it does not fully classify image meaning or every form of visual abuse.
7. **URL checks:** The current URL validator performs structural checks; it does not fetch destinations or provide live reputation verdicts.
8. **ML:** Model confidence is not automatically a calibrated probability of safety. Validate models with representative labelled data and measure false-positive/false-negative rates.
9. **Scoring parameters:** Severity points, module weights, projection scales, corroboration factor and extra-module risk are policy settings. Validate changes against a labelled evaluation set.
10. **Fail-closed behaviour:** Incomplete required inspection, confirmed blocking findings and unresolved investigation can override a favourable weighted score.
11. **Auditability:** Keep logs and database records access-controlled. Avoid logging full email bodies, passwords, tokens or sensitive attachment contents unnecessarily.
12. **Demo acknowledgement:** The warning token helper is explicitly described in source as a local demo mechanism. Production should record acknowledgement against an authenticated user/session and an audit trail.


---

## 🧹 16. Repository hygiene

The uploaded ZIP contains a developer `.venv`, Python cache files and a `.env` file. These should not be part of a clean production or public Git repository.

Recommended exclusions:

```gitignore
.env
.env.*
!.env.example
.venv/
venv/
__pycache__/
*.py[cod]
.pytest_cache/
.mypy_cache/
.ruff_cache/
.DS_Store
```

Keep required runtime artifacts such as the content rules JSON and classifier model only if the deployment configuration needs them and the organization is permitted to distribute them. Keep the denied-hash list if it is part of the configured policy, but do not place secrets in it.

Before sharing a ZIP or pushing to a remote repository:

```bash
git status
git check-ignore -v .env .venv
```

If a secret has ever been committed, adding it to `.gitignore` is not enough: rotate the secret and remove it from repository history using an approved repository-cleanup procedure.


---

## ⚡ 17. Quick start summary

```bash
# 1. Create and activate a virtual environment
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux/macOS
# source .venv/bin/activate

# 2. Install backend dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt

# 3. Configure n-omg.env (MySQL credentials and JWT secret are required)

# 4. Start the API locally
uvicorn app:app --host 127.0.0.1 --port 8000 --reload
```

Then open `http://127.0.0.1:8000/`, log in, and submit an email through the portal. For API testing, authenticate first and call `POST /api/v1/analyze` with the returned Bearer token.

---

---

<div align="center">

**🛡️ OMG — Outbound Mail Gatekeeper**  
*Backend technical documentation · Application version 3.3.0*

</div>
