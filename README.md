# OMG — Outbound Mail Gatekeeper

OMG is a FastAPI service that inspects outgoing email content before a sending application releases it to its delivery queue. Its verdict vocabulary is `SAFE`, `WARNING`, and `RESTRICTED`.

## Current capabilities

- Runtime text rules loaded from `data/omg_rules.json` for each analysis request.
- Basic HTML inspection for hidden text and selected encoded suspicious indicators.
- URL syntax/structure indicators including non-HTTP schemes, malformed URLs, embedded URL credentials, IP-address hosts, malformed hostnames, IDN/punycode hosts, and displayed/target URL mismatch.
- Local TF-IDF + Logistic Regression classifier through `models/email_classifier.joblib`. The current development package includes the existing model artifacts and local labeled CSV for continuity. Review their provenance before treating them as approved production build inputs.
- Fail-closed verdict aggregation: confirmed critical/unreviewed findings or incomplete required inspection return `RESTRICTED`; score thresholds are applied only when an explicit safety score is supplied.
- A missing score is returned as `null`; the service does not fabricate a numeric score from a clean rules result. A clean result can still be `SAFE` under the currently implemented checks, with the inspection coverage and limitations exposed.
- Shared-key authentication for analysis/status endpoints when configured; mandatory in production.
- Request IDs, security response headers, configurable request-body limit, liveness/readiness endpoints, and production startup validation.
- Optional local ClamAV (`clamscan`) attachment scanning. Supply base64 attachment bytes; if ClamAV is unavailable or scanning fails, messages with attachments are restricted.

## Important limitations

The catalog contains 156 registered definitions; only 3 are currently marked implemented. The remaining entries are catalog/requirements only, not active detectors. URL/domain reputation, DNS reputation, and sender authentication are not implemented here. ClamAV attachment scanning requires a separately installed local engine and current signatures. Heuristic findings are indicators, not proof of malicious intent. The current text model is a baseline and must be independently evaluated before production use.

## Setup (Windows PowerShell)

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
python -m pytest -q
python -m uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000/docs` during development. Endpoints: `GET /`, `GET /api/v1/health`, `GET /api/v1/ready`, `GET /api/v1/status`, and `POST /api/v1/analyze`.

## Analyze request

```json
{
  "channel": "email",
  "subject": "Team meeting",
  "html": "<p>The meeting starts at 10 AM.</p>",
  "recipients": ["recipient@example.com"],
  "attachments": []
}
```

Notify must release the message only when the HTTP response is successful and both `status == "SAFE"` and `can_send == true`. `WARNING` remains non-sendable until a secure, user-bound acknowledgement is implemented with Notify's verified identity contract. Any error, timeout, invalid response, or `RESTRICTED` verdict must block release.

## Train a local model

Prepare a reviewed CSV with columns `text,label`; accepted labels are `SAFE`/`RESTRICTED` or `HAM`/`SPAM`. Keep training and holdout datasets separate.

```powershell
python scripts/prepare_corpus.py --source "C:\path\to\extracted\corpus" --output data/labeled_emails.csv
python scripts/train_model.py --data data/labeled_emails.csv --output models/email_classifier_new.joblib
python scripts/evaluate_model.py --data data/independent_holdout.csv --model models/email_classifier.joblib
```

The stratified report from training is not a production accuracy guarantee. The SpamAssassin-derived starter corpus is small and old; it is suitable for a baseline experiment, not sufficient by itself to validate production security performance. Do not commit email datasets, secrets, or `.env`.

## Deployment

See [`docs/deployment.md`](docs/deployment.md) for production environment variables, API key handling, readiness probes, Docker use, Notify's fail-closed contract, and outstanding limitations. Production requires `OMG_ENVIRONMENT=production`, `OMG_REQUIRE_ML=true`, a trained model file, a valid rules file, and a unique `OMG_API_KEY` of at least 32 characters. Swagger/OpenAPI documentation is disabled in production by default.

## Tests

```powershell
python -m pytest -q
```


## Option B classifier upgrade

The training pipeline uses a word-level TF-IDF representation plus character-level TF-IDF n-grams with Logistic Regression. Word features capture phrases; character features can help with spelling variation and obfuscation. This is still a classical ML model, not a guarantee of detecting every phishing or malicious email.

Retrain after updating the labeled dataset. The training script refuses to overwrite an existing model unless `--force` is explicitly supplied. Prefer a new output filename so the current model remains available for rollback:

```powershell
python scripts/train_model.py --data data/labeled_emails.csv --output models/email_classifier_new.joblib --test-size 0.2
```

The API reports a model confidence when the loaded estimator supports `predict_proba`. Predictions below `OMG_ML_MIN_CONFIDENCE` are treated as `RESTRICTED` for manual review. The default is `0.60`; tune this only using validation data that is separate from the final holdout. Models that do not expose probabilities are still classified, but do not receive confidence-based handling.

Before production, evaluate on an independent, deduplicated holdout set that was not used to train or tune the model. The existing SpamAssassin ham/spam corpus is not sufficient by itself to establish phishing-specific or production-wide accuracy.


## Current release status

See [`docs/release_audit.md`](docs/release_audit.md) for the verified baseline test result, dataset counts, model-provenance limitations, implemented capabilities, and outstanding Notify integration dependencies. The current binary ML model is not connected to a validated hybrid 0-100 safety-score calculation. Raw `predict_proba()` output is model confidence, not a calibrated safety score.
