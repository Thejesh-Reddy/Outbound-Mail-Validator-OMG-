# OMG Deployment Checklist

This guide covers deploying the FastAPI inspection service. It does not claim that the whole mail product is production-complete: ClamAV attachment scanning is optional and must be installed/configured, URL reputation is not implemented, and Notify must enforce the verdict contract.

## Production prerequisites

Before setting `OMG_ENVIRONMENT=production`:

1. Put the reviewed `email_classifier.joblib` at the configured `OMG_MODEL_PATH` (default `models/email_classifier.joblib`). The current development handoff archive includes existing model artifacts and a local labeled CSV, but their full training provenance has not been established. Do not treat them as production-approved until provenance and independent evaluation are documented.
2. Review `data/omg_rules.json`; it must be present and parse successfully.
3. Configure `OMG_API_KEY` as a unique random secret of at least 32 characters. Generate one locally with `python -c "import secrets; print(secrets.token_urlsafe(32))"`. Store it in the deployment platform's secret/environment-variable manager; do not commit it or bake it into a container image.
4. Set `OMG_REQUIRE_ML=true` so a missing or failing ML model cannot silently become optional.
5. Set `OMG_ENVIRONMENT=production`.
6. Terminate TLS at the hosting platform or a trusted reverse proxy. Do not expose the service over unencrypted public HTTP.
7. Keep the model and rules read-only to the runtime process where possible. Use restricted network access and operational monitoring.

The application refuses to start in production when the API key, required ML setting, model file, or rules file is missing. Startup also loads the model and validates the rule file. The `/api/v1/ready` endpoint returns HTTP 503 if required runtime components are not ready.

## Environment variables

```text
OMG_ENVIRONMENT=production
OMG_API_PREFIX=/api/v1
OMG_RULES_PATH=data/omg_rules.json
OMG_MODEL_PATH=models/email_classifier.joblib
OMG_REQUIRE_ML=true
OMG_API_KEY=<secret of at least 32 characters>
OMG_LOG_LEVEL=INFO
OMG_MAX_REQUEST_BYTES=1200000
```

Use the hosting provider's environment settings for production. `.env` is for local development and must not be committed.

## Run locally

```powershell
Copy-Item .env.example .env
python -m pip install -r requirements.txt
python -m pytest -q
python -m uvicorn app:app --host 127.0.0.1 --port 8000
```

In development, API authentication is optional unless `OMG_API_KEY` is set. In production, API authentication is mandatory. Production disables Swagger, ReDoc, and the OpenAPI document by default.

## API authentication

Send the configured key using `X-OMG-API-Key` for `POST /api/v1/analyze` and `GET /api/v1/status`:

```powershell
$headers = @{ "X-OMG-API-Key" = $env:OMG_API_KEY }
Invoke-RestMethod -Uri "https://YOUR-OMG-HOST/api/v1/status" -Headers $headers
```

Do not place the secret in source code, URLs, query parameters, email content, or logs.

## Probes

- `GET /api/v1/health`: liveness only; it does not prove dependencies are ready.
- `GET /api/v1/ready`: checks runtime rules, catalog, and required ML model. Expect HTTP 200 only when required components are ready; otherwise HTTP 503.
- `GET /api/v1/status`: version and capability summary; requires API key when configured.

The response status describes the service, not whether a specific email is safe.

## Notify integration contract

1. Notify calls `POST /api/v1/analyze` over HTTPS with `X-OMG-API-Key`.
2. Release an outgoing email only if the response is valid JSON, HTTP status is 200, `status == "SAFE"`, and `can_send == true`.
3. Block the send on `RESTRICTED`, timeout, connection error, HTTP error, malformed response, or any missing/contradictory field. Never treat an unavailable OMG service as `SAFE`.
4. Do not retry indefinitely. Use a bounded timeout/retry policy and log the request ID returned by OMG without logging message bodies or API keys.
5. Install ClamAV and update signatures before enabling attachment sends. Set `OMG_CLAMSCAN_PATH` when `clamscan` is not on PATH. If the scanner is absent or errors, OMG blocks messages with attachments.

## WARNING acknowledgement boundary

The current API does not expose a WARNING acknowledgement endpoint. The shared OMG API key authenticates Notify as a service caller; it does not authenticate the individual sender. Do not add a client-side `acknowledged=true` flag or use the shared API key as proof of end-user consent. Implement the warning path only after Notify supplies a verifiable user identity/token contract and the design binds approval to the exact analyzed message digest, expires the approval, and prevents replay. Until then, WARNING remains non-sendable.

## Explicit limitations

- Attachment scanning requires a locally installed, updated ClamAV engine. Messages with attachments are restricted if ClamAV is unavailable or scanning does not complete.
- URL checks identify syntax/structural indicators; URL/domain reputation and live threat-intelligence lookups are not implemented.
- The text model is a baseline trained on a small, older spam/ham corpus. It is not a general-purpose phishing, malware, or policy-compliance detector.
- The catalog contains 156 registered definitions, but only 3 are currently marked implemented. Catalog entries alone do not imply runtime detection.
- Deployment is not a substitute for an independent holdout evaluation, false-positive review, security testing, and operational monitoring using representative organizational traffic.


### Classifier upgrade (Option B)

Train the word+character TF-IDF model using reviewed labels. The training script expects `text,label` columns and supports `SAFE`/`HAM` and `RESTRICTED`/`SPAM`. Do not put the final evaluation holdout into the training CSV. Configure `OMG_ML_MIN_CONFIDENCE` (default `0.60`) based on validation results. Low-confidence predictions are restricted for manual review. This is a conservative policy and may increase false positives; measure both false negatives and false positives before production.
