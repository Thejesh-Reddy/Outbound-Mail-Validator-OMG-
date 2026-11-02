"""Train the OMG binary email classifier from a reviewed labeled CSV.

Input columns: text,label. Accepted labels: SAFE/HAM and RESTRICTED/SPAM.
This script does not generate training data. Keep evaluation data independent.
"""
import argparse
from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import FeatureUnion
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

def ensure_output_available(output: Path, force: bool = False) -> None:
    """Prevent accidental replacement of an existing trained model."""
    if output.exists() and not force:
        raise SystemExit(
            f"Refusing to overwrite existing model: {output}. "
            "Choose a new --output path or pass --force after backing up the existing model."
        )


LABEL_MAP = {
    "SAFE": "SAFE",
    "HAM": "SAFE",
    "RESTRICTED": "RESTRICTED",
    "SPAM": "RESTRICTED",
}


def load_labeled_data(path: Path):
    if not path.is_file():
        raise SystemExit(
            f"Training data not found: {path}. Provide a reviewed CSV with text,label columns."
        )

    df = pd.read_csv(path)
    missing = {"text", "label"} - set(df.columns)
    if missing:
        raise SystemExit(f"CSV is missing required column(s): {', '.join(sorted(missing))}")

    df = df.dropna(subset=["text", "label"]).copy()
    df["text"] = df["text"].astype(str).str.strip()
    df["label"] = df["label"].astype(str).str.strip().str.upper().map(LABEL_MAP)
    df = df.dropna(subset=["label"])
    df = df[df["text"].ne("")]

    counts = df["label"].value_counts()
    if len(df) < 20 or set(counts.index) != {"SAFE", "RESTRICTED"} or counts.min() < 2:
        raise SystemExit(
            "Need at least 20 non-empty examples, both SAFE and RESTRICTED labels, "
            "and at least two examples in each class."
        )
    return df["text"], df["label"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", default="data/labeled_emails.csv")
    parser.add_argument("--output", default="models/email_classifier.joblib")
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument(
        "--force", action="store_true",
        help="Allow replacing an existing model file. Without this flag, training refuses to overwrite it.",
    )
    args = parser.parse_args()

    if not 0.1 <= args.test_size <= 0.4:
        raise SystemExit("--test-size must be between 0.1 and 0.4.")

    output = Path(args.output)
    ensure_output_available(output, force=args.force)

    X, y = load_labeled_data(Path(args.data))
    if y.value_counts().min() < 2:
        raise SystemExit("Each class needs at least two examples for a stratified split.")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=42, stratify=y
    )

    # Word features capture meaning and phrases; character n-grams help with
    # misspellings, obfuscation, and small variations in suspicious terms.
    model = Pipeline([
        ("features", FeatureUnion([
            ("word_tfidf", TfidfVectorizer(
                analyzer="word",
                ngram_range=(1, 2),
                max_features=100_000,
                strip_accents="unicode",
                lowercase=True,
                sublinear_tf=True,
                min_df=1,
            )),
            ("char_tfidf", TfidfVectorizer(
                analyzer="char_wb",
                ngram_range=(3, 5),
                max_features=100_000,
                strip_accents="unicode",
                lowercase=True,
                sublinear_tf=True,
                min_df=1,
            )),
        ])),
        ("classifier", LogisticRegression(
            max_iter=1000,
            class_weight=None,
            random_state=42,
        )),
    ])
    model.fit(X_train, y_train)

    print("Internal stratified split report (not a production accuracy guarantee):")
    print(classification_report(
        y_test, model.predict(X_test),
        labels=["SAFE", "RESTRICTED"], zero_division=0,
    ))
    output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, output)
    print(f"Saved model to {output.resolve()}")
    print("Before deployment, evaluate against an independent, untouched holdout dataset.")


if __name__ == "__main__":
    main()
