"""Evaluate a saved OMG classifier against an independent labeled CSV holdout."""
import argparse
from pathlib import Path

import joblib
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix

LABEL_MAP = {
    "SAFE": "SAFE",
    "HAM": "SAFE",
    "RESTRICTED": "RESTRICTED",
    "SPAM": "RESTRICTED",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", required=True, help="Independent CSV with text,label columns")
    parser.add_argument("--model", default="models/email_classifier.joblib")
    args = parser.parse_args()

    data_path = Path(args.data)
    model_path = Path(args.model)
    if not data_path.is_file():
        raise SystemExit(f"Evaluation data not found: {data_path}")
    if not model_path.is_file():
        raise SystemExit(f"Trained model not found: {model_path}")

    df = pd.read_csv(data_path)
    missing = {"text", "label"} - set(df.columns)
    if missing:
        raise SystemExit(f"CSV is missing required column(s): {', '.join(sorted(missing))}")

    df = df.dropna(subset=["text", "label"]).copy()
    df["text"] = df["text"].astype(str).str.strip()
    df["label"] = df["label"].astype(str).str.strip().str.upper().map(LABEL_MAP)
    df = df.dropna(subset=["label"])
    df = df[df["text"].ne("")]
    if df.empty:
        raise SystemExit("No valid labeled examples remain after cleaning.")

    model = joblib.load(model_path)
    y_true = df["label"]
    y_pred = model.predict(df["text"])
    unexpected = set(y_pred) - {"SAFE", "RESTRICTED"}
    if unexpected:
        raise SystemExit(f"Model returned unsupported labels: {sorted(unexpected)}")

    print("Independent holdout evaluation (results apply only to this dataset):")
    print(classification_report(
        y_true, y_pred, labels=["SAFE", "RESTRICTED"], zero_division=0
    ))
    print("Confusion matrix [rows=true SAFE/RESTRICTED, columns=predicted SAFE/RESTRICTED]:")
    print(confusion_matrix(y_true, y_pred, labels=["SAFE", "RESTRICTED"]))


if __name__ == "__main__":
    main()
