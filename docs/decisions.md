# Design Decisions and Limitations

- Verdict vocabulary is `SAFE`, `WARNING`, and `RESTRICTED`.
- Safety score thresholds are `<75` = `RESTRICTED`, `75` to `<86` = `WARNING`, and `>=86` = `SAFE`.
- Fail closed: confirmed critical findings, unknown/unreviewed finding codes, required-inspection failures, API failures, invalid responses, and incomplete attachment scans must not permit sending.
- Finding actions are centralized in `app/pipeline/finding_policy.py`. The three catalog entries currently marked implemented (`LOTTERY_SCAM`, `CREDENTIAL_PHISHING`, and `URL_CREDENTIALS_IN_AUTHORITY`) retain their catalog default action of `RESTRICTED_IF_CONFIRMED_OR_REQUIRED_CHECK_INCOMPLETE`.
- No finding codes are currently approved for `WARNING` or `INFORMATIONAL`; unknown codes default to `RESTRICTED`. This conservative policy avoids silently downgrading existing protections. Warning eligibility requires documented policy review and tests.
- Runtime rules are editable JSON so text rules can be updated without source edits. Changes require review and tests.
- The local ML model is optional in development for local testing; production startup requires `OMG_REQUIRE_ML=true` and a loadable model file.
- Raw classifier confidence is not a calibrated safety score. Hybrid scoring must not use it as a probability until calibration and independent evaluation are completed.
- API-key authentication is optional in development and mandatory in production. The key is sent using `X-OMG-API-Key`.
- The 156-entry catalog is a registered catalog, not 156 implemented detectors. Only entries explicitly marked implemented have mapped runtime implementations in this version.
- The teammate-owned attachment scanner is a placeholder. Emails with attachments are restricted until integration returns a valid complete-safe result.
- URL reputation, DNS/domain reputation, and sender-authentication checks are not implemented by this repository.
- No accuracy or latency claim is made without empirical evaluation on representative independent data.
- Notify's existing delivery queue remains in place; OMG does not introduce another queue service.
- Secure, user-bound WARNING acknowledgement is deferred until Notify's authenticated identity integration is confirmed. Until then, WARNING remains non-sendable (`can_send=false`).
