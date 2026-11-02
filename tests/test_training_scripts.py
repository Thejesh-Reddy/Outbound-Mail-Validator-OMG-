import pandas as pd
import pytest

from model_training.train_model import load_labeled_data


def test_training_data_maps_only_exact_supported_labels(tmp_path):
    csv_path = tmp_path / "emails.csv"
    texts = [f"safe note {i}" for i in range(10)] + [f"restricted message {i}" for i in range(10)]
    labels = ["SAFE"] * 5 + ["HAM"] * 5 + ["RESTRICTED"] * 5 + ["SPAM"] * 5
    pd.DataFrame({"text": texts, "label": labels}).to_csv(csv_path, index=False)

    loaded_texts, loaded_labels = load_labeled_data(csv_path)

    assert len(loaded_texts) == 20
    assert list(loaded_labels).count("SAFE") == 10
    assert list(loaded_labels).count("RESTRICTED") == 10


def test_training_data_rejects_missing_columns(tmp_path):
    csv_path = tmp_path / "emails.csv"
    pd.DataFrame({"message": ["hello"], "class": ["SAFE"]}).to_csv(csv_path, index=False)

    with pytest.raises(SystemExit, match="missing required column"):
        load_labeled_data(csv_path)


def test_training_data_rejects_single_class(tmp_path):
    csv_path = tmp_path / "emails.csv"
    pd.DataFrame({
        "text": [f"message {i}" for i in range(20)],
        "label": ["SAFE"] * 20,
    }).to_csv(csv_path, index=False)

    with pytest.raises(SystemExit, match="both SAFE and RESTRICTED"):
        load_labeled_data(csv_path)


def test_training_refuses_to_overwrite_existing_model_without_force(tmp_path):
    from model_training.train_model import ensure_output_available

    existing = tmp_path / "existing.joblib"
    existing.write_bytes(b"keep this model")

    with pytest.raises(SystemExit, match="Refusing to overwrite"):
        ensure_output_available(existing)

    assert existing.read_bytes() == b"keep this model"


def test_training_allows_explicit_force_for_existing_model(tmp_path):
    from model_training.train_model import ensure_output_available

    existing = tmp_path / "existing.joblib"
    existing.write_bytes(b"keep this model")
    ensure_output_available(existing, force=True)
    assert existing.read_bytes() == b"keep this model"
