# OMG — Outbound Mail Gatekeeper

OMG is a FastAPI service for inspecting outgoing email content before Notify releases it.

## Detection design

- No LLM and no trained ML classifier are used.
- `email_classifier.py` uses scikit-learn's `TfidfVectorizer` only to extract class-associated words and phrases from labelled examples.
- The offline process writes a versioned JSON pattern catalogue to `patterns/pattern_catalog.json`.
- `Content/text_validator.py` performs deterministic runtime matching against that catalogue.
- `Content/html_validator.py` checks HTML structure (hidden text and password-capture forms).
- `URL/url_validator.py` performs structural URL checks; live domain reputation is not implemented.
- `decision_making.py` combines findings and returns SAFE, WARNING or RESTRICTED.

## Included dataset — important limitation

`labeled_emails.csv` is a **synthetic starter/demo dataset** containing 30 SAFE and 30 RESTRICTED examples. It was created to make the training pipeline runnable because no original historical labelled dataset was present in the supplied ZIP.

It is not an independently collected historical corpus, does not establish real-world accuracy, and must not be used to claim 98%, 99% or any production accuracy. Replace or substantially expand it with approved, representative, labelled historical emails before production evaluation.

## Setup (Windows PowerShell)

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Generate / refresh the pattern catalogue

Run from the OMG project root:

```powershell
python email_classifier.py --train
```

Optional paths:

```powershell
python email_classifier.py --train --data labeled_emails.csv --output patterns/pattern_catalog.json
```

The generated catalogue is required at runtime. The training command is run offline; the API does not retrain for every email.

## Run the API

```powershell
uvicorn app:app --reload
```

Open `http://127.0.0.1:8000/docs` and use `POST /api/v1/analyze`.

Set `OMG_API_KEY` in `.env` if Notify integration requires API-key authentication. Production mode requires an API key of at least 32 characters and an existing pattern catalogue.

## Verdict policy

- SAFE: score >= 86 and no warning/restricted finding.
- WARNING: score 75–85.99 or a warning-eligible finding. The response includes a finding-based explanation, `requires_acknowledgement: true`, and `can_send: true` to indicate that sending is permitted only after explicit user confirmation. The popup actions are `SEND_ANYWAY` and `EDIT_MAIL`.
- RESTRICTED: score < 75, a restricted finding, or an inspection failure. `can_send` is false and delivery must be blocked.

Notify integration must follow this gate:
- SAFE + `can_send == true`: send directly.
- WARNING + `can_send == true` + `requires_acknowledgement == true`: show the warning popup and send only after the user explicitly selects `SEND_ANYWAY`. `EDIT_MAIL` returns to the editor. Never send a WARNING email automatically.
- RESTRICTED or any API error/timeout/invalid response: block sending.

## Dataset format

CSV columns: `subject`, `body`, `label`. Labels accepted by the training process include SAFE/VALID/HAM and RESTRICTED/SPAM/PHISHING.
