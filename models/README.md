# Local model artifacts

This development package currently contains `email_classifier.joblib` and `email_classifier_balanced_backup.joblib`. Both are trusted serialized scikit-learn artifacts; never load a model supplied by an untrusted party.

The model artifacts report scikit-learn serialization version 1.9.1. Install the pinned project dependency (`scikit-learn==1.9.1`) before loading them. Loading with a different scikit-learn version can produce compatibility warnings or unpredictable behavior.

## Provenance status

The repository contains `scripts/train_model.py`, which trains the primary model from a `text,label` CSV using a stratified split and `class_weight=None`. The source tree does not contain a script or recorded command explaining the creation of `email_classifier_balanced_backup.joblib`. The exact training date, data snapshot, split membership, and training command for either currently packaged model have not been established. Do not describe the backup as a verified balanced model solely from its filename.

Before production approval, record the training-data source and license, preprocessing version, training command, dependency versions, evaluation results on an untouched representative holdout, and SHA-256 checksum. Evaluate false negatives and class-specific metrics, not accuracy alone.
