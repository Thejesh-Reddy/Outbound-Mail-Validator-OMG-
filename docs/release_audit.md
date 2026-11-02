# OMG release audit — uploaded project baseline

## Verification performed

- Inspected the uploaded project archive and its source, tests, documentation, data files, and model artifacts.
- Ran the complete test suite in the review environment after the attachment-scanning upgrade: **83 passed**.
- The review environment emitted 10 scikit-learn `InconsistentVersionWarning` warnings because its installed version was 1.8.0 while the model artifacts were serialized with 1.9.1. Both development and runtime requirements are pinned to 1.9.1 to match the artifacts. The test environment could not be upgraded during this run; rerun tests in a clean environment after installing the pinned requirements.

## Dataset facts

The packaged `data/labeled_emails.csv` has 2,951 rows with columns `text,label`: 2,473 `SAFE` and 478 `RESTRICTED`.

The local raw corpus described during project review contained 2,501 files under `ham` and 501 under `spam` (3,002 total). `scripts/prepare_corpus.py` maps ham to SAFE and spam to RESTRICTED, and skips unreadable, short, and duplicate files. The 51-row difference is consistent with those documented skip conditions, but the individual skipped records and exact reasons have not been audited.

`data/README.md` describes a SpamAssassin-style corpus and suggests an Rspamd test-corpus release as a starter source. The exact provenance, download URL/version, license evidence, and checksums for the local 3,002 raw files are not recorded in the package. Do not infer a confirmed source/license from the folder naming alone.

## Model provenance facts

- `scripts/train_model.py` trains `models/email_classifier.joblib` by default from `data/labeled_emails.csv`, using an 80/20 stratified split by default, `random_state=42`, word and character TF-IDF, Logistic Regression, and `class_weight=None`.
- The script can overwrite its output path; the updated script now refuses to overwrite an existing model unless `--force` is explicitly passed. Prefer a new candidate output filename.
- No Python source file in the uploaded project references `email_classifier_balanced_backup.joblib` as an output. Its creation procedure is not documented.
- The uploaded models are serialized with scikit-learn 1.9.1. The review runtime used 1.8.0 and emitted compatibility warnings. The project dependency is pinned to 1.9.1 to match the artifacts.
- It is not yet proven which CSV snapshot or split trained either packaged model. Do not evaluate either model against the full `labeled_emails.csv` and call that an independent holdout. Do not replace either model until provenance and a valid holdout are established.

## Verdict and scoring status

- Verdicts are `SAFE`, `WARNING`, and `RESTRICTED`.
- If a numeric safety score is explicitly supplied, thresholds are `<75` RESTRICTED, `75` to `<86` WARNING, and `>=86` SAFE.
- Mandatory inspection failures and hard-block findings override any score.
- Raw classifier `predict_proba()` output is not a calibrated safety score. The live orchestrator does not currently calculate a validated hybrid score from rules and ML.
- The decision aggregator no longer fabricates a score of 100 when no score is supplied; `confidence_score` is `null` in that case. A clean rules result may still be SAFE under the implemented checks, but that must not be described as a completed hybrid ML verdict.
- Unknown finding codes fail closed. No finding codes are currently approved for WARNING or INFORMATIONAL treatment.

## Integration dependencies not included in this package

1. Notify must send requests using the agreed service authentication and must release only when the response is successful, `status == SAFE`, and `can_send == true`.
2. A secure WARNING acknowledgement cannot be implemented correctly until Notify provides a verifiable end-user identity contract. A shared OMG API key authenticates the service caller, not the user. WARNING therefore remains non-sendable.
3. Optional ClamAV attachment scanning is now implemented. It requires a locally installed ClamAV executable and current signatures; when unavailable or incomplete, attachments fail closed. This environment did not have ClamAV installed, so live malware-signature scanning was not exercised; adapter behaviour was tested with controlled scanner responses.
4. URL/domain reputation, DNS reputation, sender authentication, and several catalog-only patterns are not implemented.
5. The 156-entry catalog is not 156 active detectors; only 3 entries are marked implemented.

## Release decision

This package is suitable for continued development and teammate API integration testing in a controlled environment. It is **not yet approved as production-ready** until the model provenance/evaluation, attachment scanner, Notify identity/acknowledgement contract, and required security integrations are resolved and tested.
