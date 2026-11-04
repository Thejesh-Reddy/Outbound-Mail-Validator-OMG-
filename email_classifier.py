"""Offline TF-IDF pattern extraction and deterministic runtime scoring.

This module does NOT train or load an ML classifier. TF-IDF is used only to
extract discriminative words/phrases from a labelled CSV. Runtime decisions
are made by deterministic catalogue matching in Content/text_validator.py.

Run:
    python email_classifier.py --train
    python email_classifier.py --train --data labeled_emails.csv
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import re
from collections import Counter
from pathlib import Path

from bs4 import BeautifulSoup
from sklearn.feature_extraction.text import TfidfVectorizer

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DATASET = BASE_DIR / "labeled_emails.csv"
DEFAULT_CATALOG = BASE_DIR / "patterns" / "pattern_catalog.json"
logger = logging.getLogger(__name__)

LABEL_ALIASES = {
    "SAFE": "SAFE", "VALID": "SAFE", "HAM": "SAFE", "LEGITIMATE": "SAFE",
    "RESTRICTED": "RESTRICTED", "SPAM": "RESTRICTED", "PHISHING": "RESTRICTED",
}


class PatternTrainingError(ValueError):
    """Raised when the labelled dataset cannot produce a usable catalogue."""


def email_to_text(subject: str, body: str) -> str:
    visible = BeautifulSoup(body or "", "html.parser").get_text(" ", strip=True)
    return re.sub(r"\s+", " ", f"{subject or ''} {visible}").strip().lower()


def _read_dataset(path: Path) -> tuple[list[str], list[str]]:
    if not path.is_file():
        raise PatternTrainingError(f"Labelled dataset not found: {path}")
    texts: list[str] = []
    labels: list[str] = []
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {"subject", "body", "label"}
        if not reader.fieldnames or not required.issubset(set(reader.fieldnames)):
            raise PatternTrainingError(
                "CSV must contain these columns: subject, body, label."
            )
        for row_number, row in enumerate(reader, start=2):
            label_raw = str(row.get("label") or "").strip().upper()
            label = LABEL_ALIASES.get(label_raw)
            text = email_to_text(str(row.get("subject") or ""), str(row.get("body") or ""))
            if not label or not text:
                logger.warning("Skipping empty or unsupported row %s", row_number)
                continue
            texts.append(text)
            labels.append(label)

    counts = Counter(labels)
    if counts["SAFE"] < 2 or counts["RESTRICTED"] < 2:
        raise PatternTrainingError(
            "At least two labelled examples for both SAFE and RESTRICTED are required."
        )
    return texts, labels


def train_pattern_catalog(
    dataset_path: str | Path = DEFAULT_DATASET,
    output_path: str | Path = DEFAULT_CATALOG,
    max_patterns_per_class: int = 120,
) -> dict:
    """Extract class-associated TF-IDF terms/phrases; no classifier is fitted."""
    dataset = Path(dataset_path)
    output = Path(output_path)
    texts, labels = _read_dataset(dataset)

    vectorizer = TfidfVectorizer(
        lowercase=True,
        strip_accents="unicode",
        ngram_range=(1, 3),
        min_df=2,
        max_df=0.98,
        sublinear_tf=True,
        token_pattern=r"(?u)\b[a-zA-Z][a-zA-Z0-9'-]{1,}\b",
        stop_words="english",
    )
    matrix = vectorizer.fit_transform(texts)
    terms = vectorizer.get_feature_names_out()
    safe_indices = [i for i, label in enumerate(labels) if label == "SAFE"]
    restricted_indices = [i for i, label in enumerate(labels) if label == "RESTRICTED"]

    safe_mean = matrix[safe_indices].mean(axis=0).A1
    restricted_mean = matrix[restricted_indices].mean(axis=0).A1
    patterns: list[dict] = []

    for class_name, positive, negative in (
        ("SAFE", safe_mean, restricted_mean),
        ("RESTRICTED", restricted_mean, safe_mean),
    ):
        differences = positive - negative
        candidates = [
            (idx, float(score))
            for idx, score in enumerate(differences)
            if score > 0.002
        ]
        candidates.sort(key=lambda item: item[1], reverse=True)
        selected = candidates[:max_patterns_per_class]
        max_score = max((score for _, score in selected), default=1.0)
        for idx, score in selected:
            patterns.append({
                "pattern": str(terms[idx]),
                "class": class_name,
                "weight": round(score / max_score, 5),
                "supporting_documents": int(
                    (matrix[:, idx].toarray().ravel() > 0).sum()
                ),
            })

    if not patterns:
        raise PatternTrainingError("No discriminative patterns were extracted.")

    catalogue = {
        "catalogue_version": 1,
        "method": "TF-IDF discriminative n-gram extraction with deterministic matching",
        "classifier": None,
        "training_rows": len(texts),
        "label_counts": dict(Counter(labels)),
        "dataset_name": dataset.name,
        "dataset_notice": (
            "The included starter dataset is synthetic demonstration data. "
            "It is not an independently collected historical email corpus and "
            "must not be used to claim production accuracy."
        ),
        "patterns": patterns,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(json.dumps(catalogue, indent=2, ensure_ascii=False), encoding="utf-8")
    temporary.replace(output)
    return catalogue


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate OMG's TF-IDF pattern catalogue.")
    parser.add_argument("--train", action="store_true", help="Extract patterns from the labelled CSV.")
    parser.add_argument("--data", default=str(DEFAULT_DATASET), help="Path to labelled CSV.")
    parser.add_argument("--output", default=str(DEFAULT_CATALOG), help="Output catalogue JSON path.")
    args = parser.parse_args()
    if not args.train:
        parser.error("Use --train to generate the pattern catalogue.")
    catalogue = train_pattern_catalog(args.data, args.output)
    print(
        f"Generated {len(catalogue['patterns'])} patterns from "
        f"{catalogue['training_rows']} labelled emails: {args.output}"
    )
    print("Dataset is synthetic starter data; do not treat this as production validation.")


if __name__ == "__main__":
    main()
