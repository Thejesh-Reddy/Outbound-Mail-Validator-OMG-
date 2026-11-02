# Architecture

1. Notify's outgoing-message flow calls OMG before releasing a message to its existing delivery queue.
2. The request schema validates channel, subject, HTML/body, recipient addresses, and attachment metadata. Request size is capped by `OMG_MAX_REQUEST_BYTES`.
3. Runtime text rules inspect subject/body; HTML checks inspect selected hidden/encoded indicators; URL checks inspect link syntax/structure; the local TF-IDF + Logistic Regression classifier classifies text when a trained model is available.
4. Attachment metadata is passed through a defined interface to the teammate-owned scanner. Until that scanner is integrated, messages with attachments are `RESTRICTED`; messages without attachments report scanning as not applicable.
5. The decision aggregator applies the three-state thresholds when an explicit numeric safety score is supplied: below 75 is `RESTRICTED`, 75 to below 86 is `WARNING`, and 86 or above is `SAFE`. Mandatory inspection failures and restricted findings override the numeric score. When no score is supplied, the response uses `confidence_score: null` rather than fabricating 100; a clean result may pass only the currently implemented mandatory inspections.
6. Finding actions are centralized in `app/pipeline/finding_policy.py`. The three catalog entries marked implemented retain their restrictive default action. Unknown or unreviewed finding codes fail closed. No warning-level finding code is approved yet.
7. The hybrid score design combines a rule-derived safety score and a calibrated ML safety score. Raw `predict_proba()` confidence is not a calibrated safety score and must not be used as one before calibration and independent evaluation. The live orchestrator has not yet been connected to this hybrid scoring calculation.
8. `WARNING` is not sendable until a secure server-side acknowledgement flow is implemented and integrated with Notify's authenticated user identity. Notify must block sending on any API failure or any response other than an explicit `SAFE` verdict with `can_send=true`, unless the later approved acknowledgement contract explicitly authorizes the warning path.
9. Production requires a shared API key and `OMG_REQUIRE_ML=true`; startup validates required configuration and loads the model and rules before serving traffic.

## Operational endpoints

- `/api/v1/health`: liveness only.
- `/api/v1/ready`: checks runtime rules, pattern catalog, and required ML model readiness.
- `/api/v1/status`: version/capability summary; authenticated when an API key is configured.

## Current gaps

No URL/domain reputation service, no actual attachment scanner, no sender-authentication integration, no Notify user-identity integration for acknowledgements, and no validated hybrid safety-score implementation. Only 3 of 156 catalog definitions are marked implemented. The text classifier is not a general malware detector and does not prove an email is harmless.
