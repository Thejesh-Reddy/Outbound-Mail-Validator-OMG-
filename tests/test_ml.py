from app.ml.preprocessing import email_to_text
from app.ml.classifier import classify_email


def test_preprocessing_extracts_visible_html_text():
    assert email_to_text("Hello", "<p>World</p>") == "Hello World"


def test_classifier_reports_missing_model_instead_of_fake_prediction(monkeypatch, tmp_path):
    from app.core.config import settings
    from app.ml.model_loader import clear_model_cache
    monkeypatch.setattr(settings, "MODEL_PATH", tmp_path / "missing.joblib")
    clear_model_cache()
    result = classify_email("Hello", "<p>World</p>")
    assert result["completed"] is False
    assert result["finding"] is None
    clear_model_cache()


def test_low_confidence_prediction_is_restricted_for_review(monkeypatch, tmp_path):
    import app.ml.classifier as classifier_module
    from app.core.config import settings

    class FakeModel:
        classes_ = ["SAFE", "RESTRICTED"]

        def predict(self, texts):
            return ["SAFE"]

        def predict_proba(self, texts):
            return [[0.54, 0.46]]

    monkeypatch.setattr(settings, "MODEL_PATH", tmp_path / "fake.joblib")
    monkeypatch.setattr(settings, "ML_MIN_CONFIDENCE", 0.60)
    monkeypatch.setattr(classifier_module, "load_model", lambda _path: FakeModel())

    result = classifier_module.classify_email("Hello", "<p>Meeting notes</p>")

    assert result["completed"] is True
    assert result["label"] == "RESTRICTED"
    assert result["confidence"] == 0.54
    assert result["finding"]["code"] == "ML_CLASSIFIER_LOW_CONFIDENCE"


def test_high_confidence_safe_prediction_remains_safe(monkeypatch, tmp_path):
    import app.ml.classifier as classifier_module
    from app.core.config import settings

    class FakeModel:
        classes_ = ["SAFE", "RESTRICTED"]

        def predict(self, texts):
            return ["SAFE"]

        def predict_proba(self, texts):
            return [[0.96, 0.04]]

    monkeypatch.setattr(settings, "MODEL_PATH", tmp_path / "fake.joblib")
    monkeypatch.setattr(settings, "ML_MIN_CONFIDENCE", 0.60)
    monkeypatch.setattr(classifier_module, "load_model", lambda _path: FakeModel())

    result = classifier_module.classify_email("Hello", "<p>Meeting notes</p>")

    assert result["completed"] is True
    assert result["label"] == "SAFE"
    assert result["confidence"] == 0.96
    assert result["finding"] is None
