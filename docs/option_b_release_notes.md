# OMG Option B – Classifier Upgrade Notes

## Included in this update

- Word-level TF-IDF features for terms and short phrases.
- Character-level TF-IDF n-grams to help learn spelling variation and obfuscated text.
- Logistic Regression classifier retained as a lightweight local model.
- Optional probability reporting and configurable low-confidence restriction (`OMG_ML_MIN_CONFIDENCE`, default `0.60`).
- Low-confidence predictions from probability-capable models return `RESTRICTED` with `ML_CLASSIFIER_LOW_CONFIDENCE`.
- Training and evaluation scripts remain local and use labeled CSV files.
- Attachment scanning remains a teammate-owned placeholder and must fail closed until implemented.

## Retrain the model

The model file is intentionally not bundled. Copy the existing labeled dataset into `data/labeled_emails.csv`, or pass its actual path to the training command:

```powershell
python model_training/train_model.py --data data/labeled_emails.csv --output models/email_classifier.joblib --test-size 0.2
```

Do not use the final holdout set for training or threshold tuning. After training, evaluate against a separate, deduplicated labeled holdout CSV:

```powershell
python model_training/evaluate_model.py --data data/independent_holdout.csv --model models/email_classifier.joblib
```

## Threshold warning

`0.60` is a configurable starting point, not a validated optimum. A low threshold can let uncertain messages through; a high threshold can block legitimate messages. Tune it using validation data and report false-negative and false-positive rates. Probability scores are not necessarily calibrated probabilities.

## Scope limitation

The current labels are binary (`SAFE`/`RESTRICTED`, with `HAM`/`SPAM` aliases). Training on a general ham/spam corpus does not by itself provide reliable phishing-specific, impersonation, URL-reputation, or attachment-malware detection. Expand and independently evaluate the labeled dataset for those threat classes before making such claims.
