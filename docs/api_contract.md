# API Contract

## `POST /api/v1/analyze`

Requires `X-OMG-API-Key` when `OMG_API_KEY` is configured; production requires this key. Request fields: `channel` (must be `email`), non-empty `subject`, HTML/body string in `html`, one or more `recipients`, and optional `attachments` list. Each attachment must include `filename`, optional `content_type`, and `content_base64` (base64-encoded file bytes) when ClamAV scanning is configured. Metadata without bytes is never treated as scanned.

Response fields:
- `status`: exactly `SAFE`, `WARNING`, or `RESTRICTED`.
- `can_send`: true only for SAFE at the analysis stage. WARNING is initially not sendable.
- `confidence_score`: optional safety score from 0 to 100; higher means safer. It is `null` when no validated scoring component supplied a score. It is not a calibrated probability unless independently calibrated and validated.
- `warning_required`: true for WARNING.
- `requires_acknowledgement`: true for WARNING.
- `patterns_detected`: unique finding codes.
- `findings`: list of `{code, category, message}`.
- `inspection_coverage`: current component coverage and catalog counts.
- `model_version`: active classifier/version label.

### Verdict policy

When a numeric safety score is supplied:
- `confidence_score < 75`: RESTRICTED.
- `75 <= confidence_score < 86`: WARNING.
- `confidence_score >= 86`: SAFE.

When no score is supplied, OMG does not invent a value such as 100. A clean result may be `SAFE` only when the currently implemented required inspections complete without blocking findings. The response returns `confidence_score: null`; this is a rules/inspection result, not a completed hybrid score.
- A mandatory inspection failure, incomplete attachment scan, or currently blocking finding overrides the score and returns RESTRICTED.
- WARNING must remain non-sendable until a separate, authenticated acknowledgement flow is implemented and verified. The current API does not yet provide that acknowledgement flow.

Notify must not release an email based on the analysis response alone unless `status == "SAFE"` and `can_send == true`. WARNING acknowledgement support is a pending integration step; do not treat a client-side flag as authorization. A secure implementation must bind acknowledgement to Notify's verified user identity, the exact analysis/message digest, a short expiry, and one-time use. OMG's current shared API key authenticates the calling service, not the end user, and is not sufficient proof of user acknowledgement. Any HTTP validation error, authentication error, timeout, unavailable API, malformed response, or contradictory response must block the send. Do not interpret an API error as SAFE.

## Health and readiness

- `GET /api/v1/health`: public liveness probe only.
- `GET /api/v1/ready`: public readiness probe; HTTP 503 when required components are not ready.
- `GET /api/v1/status`: capability/version summary; requires the API key when configured.

Production disables interactive API documentation by default. All public deployment traffic must use HTTPS.


## Attachment scanning (ClamAV)

OMG can invoke the locally installed ClamAV `clamscan` executable. Install ClamAV, update its virus definitions, and set `OMG_CLAMSCAN_PATH` if the executable is not on PATH. Optional `OMG_ATTACHMENT_SCAN_TIMEOUT` defaults to 30 seconds. Attachment bytes are supplied as base64 in `content_base64`; client-supplied filesystem paths are never read. Per-file size is limited to 25 MiB and total attachment bytes to 45 MiB. The request-body limit defaults to 65 MB to allow base64 overhead. If ClamAV is missing, times out, errors, or attachment bytes are absent/invalid, the email is RESTRICTED. ClamAV results depend on installed engine and signature freshness; this is not a guarantee against all malware.
