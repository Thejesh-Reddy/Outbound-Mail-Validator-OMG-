# Local model artifacts

This organized project contains the primary `email_classifier.joblib` model used by the application. It is a trusted serialized scikit-learn artifact; never load a model supplied by an untrusted party.

The model artifacts report scikit-learn serialization version 1.9.1. Install the pinned project dependency (`scikit-learn==1.9.1`) before loading them. Loading with a different scikit-learn version can produce compatibility warnings or unpredictable behavior.

## Provenance status

The repository contains `model_training/train_model.py`, which trains the primary model from a `text,label` CSV using a stratified split and `class_weight=None`. The exact training date, data snapshot, split membership, and training command for the currently packaged model have not been established.

Before production approval, record the training-data source and license, preprocessing version, training command, dependency versions, evaluation results on an untouched representative holdout, and SHA-256 checksum. Evaluate false negatives and class-specific metrics, not accuracy alone.
