# Notify integration checklist

This document defines the integration boundary for the Notify team. Notify remains the sender of record; OMG only inspects and returns a verdict.

## Request

- Call `POST /api/v1/analyze` over HTTPS from the Notify backend, not directly from an untrusted browser.
- Send `X-OMG-API-Key` using a secret stored server-side.
- Send `channel`, `subject`, `html`, `recipients`, and `attachments`.
- For attachments, send the actual bytes as base64 in `attachments[].content_base64`. Do not send a local filesystem path. Metadata-only attachments are not scanned and are blocked.
- Preserve the exact message payload and recipients that were analyzed. Any edit after analysis requires a new analysis.

## Release decision

Release only if all of these are true:

1. OMG returned HTTP 200.
2. The response is valid and conforms to the response schema.
3. `status == "SAFE"`.
4. `can_send == true`.

Block delivery for WARNING, RESTRICTED, HTTP errors, timeouts, connection failures, malformed responses, or contradictory fields. Never interpret an error as SAFE. WARNING is not sendable in the current release.

## WARNING acknowledgement dependency

A secure acknowledgement endpoint is intentionally not exposed yet. Before implementing it, Notify must provide a server-verifiable identity contract (for example, a signed service assertion containing immutable user ID, tenant ID, issuer, audience, and expiry). A shared OMG API key alone authenticates Notify as a service and does not prove which end user acknowledged the warning.

The future acknowledgement must be bound to:

- the verified Notify user and tenant;
- the exact normalized message/recipient digest that received WARNING;
- the original analysis identifier and findings;
- a short expiry and one-time use;
- server-side replay protection and audit logging.

Notify must not implement acknowledgement using a browser-only boolean or a client-supplied user ID.

## Attachment deployment dependency

Install ClamAV on the OMG host, update its signatures, and configure `OMG_CLAMSCAN_PATH` if `clamscan` is not on PATH. Confirm `/api/v1/ready` and `/api/v1/status` report the scanner as configured. Keep attachments blocked if the scanner is unavailable.

## Current known limitations

- URL/domain reputation and DNS reputation are not implemented.
- SPF/DKIM/DMARC sender authentication checks are not implemented.
- The model does not provide a validated hybrid 0–100 safety score; `confidence_score` may be null.
- WARNING remains non-sendable until the identity and acknowledgement contract is implemented and tested.
