from ml_classifier.preprocessing import email_to_text
from ml_classifier.classifier import classify_email

def test_ml__test_preprocessing_extracts_visible_html_text():
    assert email_to_text('Hello', '<p>World</p>') == 'Hello World'

def test_ml__test_classifier_reports_missing_model_instead_of_fake_prediction(monkeypatch, tmp_path):
    from common.config import settings
    from ml_classifier.model_loader import clear_model_cache
    monkeypatch.setattr(settings, 'MODEL_PATH', tmp_path / 'missing.joblib')
    clear_model_cache()
    result = classify_email('Hello', '<p>World</p>')
    assert result['completed'] is False
    assert result['finding'] is None
    clear_model_cache()

def test_ml__test_low_confidence_prediction_is_restricted_for_review(monkeypatch, tmp_path):
    import ml_classifier.classifier as classifier_module
    from common.config import settings

    class FakeModel:
        classes_ = ['SAFE', 'RESTRICTED']

        def predict(self, texts):
            return ['SAFE']

        def predict_proba(self, texts):
            return [[0.54, 0.46]]
    monkeypatch.setattr(settings, 'MODEL_PATH', tmp_path / 'fake.joblib')
    monkeypatch.setattr(settings, 'ML_MIN_CONFIDENCE', 0.6)
    monkeypatch.setattr(classifier_module, 'load_model', lambda _path: FakeModel())
    result = classifier_module.classify_email('Hello', '<p>Meeting notes</p>')
    assert result['completed'] is True
    assert result['label'] == 'RESTRICTED'
    assert result['confidence'] == 0.54
    assert result['finding']['code'] == 'ML_CLASSIFIER_LOW_CONFIDENCE'

def test_ml__test_high_confidence_safe_prediction_remains_safe(monkeypatch, tmp_path):
    import ml_classifier.classifier as classifier_module
    from common.config import settings

    class FakeModel:
        classes_ = ['SAFE', 'RESTRICTED']

        def predict(self, texts):
            return ['SAFE']

        def predict_proba(self, texts):
            return [[0.96, 0.04]]
    monkeypatch.setattr(settings, 'MODEL_PATH', tmp_path / 'fake.joblib')
    monkeypatch.setattr(settings, 'ML_MIN_CONFIDENCE', 0.6)
    monkeypatch.setattr(classifier_module, 'load_model', lambda _path: FakeModel())
    result = classifier_module.classify_email('Hello', '<p>Meeting notes</p>')
    assert result['completed'] is True
    assert result['label'] == 'SAFE'
    assert result['confidence'] == 0.96
    assert result['finding'] is None
from Content.pattern_catalog import get_patterns, get_catalog_summary, load_pattern_catalog

def test_pipeline__test_catalog_contains_156_entries():
    catalog = load_pattern_catalog()
    assert catalog['pattern_count'] == 156
    assert len(catalog['patterns']) == 156

def test_pipeline__test_catalog_ids_are_unique():
    patterns = get_patterns()
    ids = [pattern['id'] for pattern in patterns]
    assert len(ids) == len(set(ids))

def test_pipeline__test_catalog_codes_are_unique():
    patterns = get_patterns()
    codes = [pattern['code'] for pattern in patterns]
    assert len(codes) == len(set(codes))

def test_pipeline__test_catalog_summary_counts_are_consistent():
    summary = get_catalog_summary()
    assert summary['total_patterns'] == 156
    assert summary['implemented_patterns'] + summary['catalog_only_patterns'] == summary['total_patterns']
from model_training.prepare_corpus import extract_body

def test_prepare_corpus__test_extract_body_keeps_subject_and_body_and_ignores_headers():
    raw = b'From: sender@example.com\nSubject: Account notice\nContent-Type: text/plain; charset=utf-8\n\nPlease review your account.'
    text, subject = extract_body(raw)
    assert subject == 'Account notice'
    assert 'Account notice' in text
    assert 'Please review your account.' in text
    assert 'sender@example.com' not in text

def test_prepare_corpus__test_extract_body_handles_html():
    raw = b'Subject: Offer\nContent-Type: text/html; charset=utf-8\n\n<html><body><p>Limited offer</p></body></html>'
    text, _ = extract_body(raw)
    assert 'Limited offer' in text
    assert '<p>' not in text

def test_prepare_corpus__test_corpus_files_with_nonstandard_suffix_are_included(tmp_path):
    from model_training.prepare_corpus import main
    import os
    source = tmp_path / 'corpus'
    (source / 'ham').mkdir(parents=True)
    (source / 'spam').mkdir(parents=True)
    (source / 'ham' / '00001.abc123').write_bytes(b"From: friend@example.com\nSubject: Meeting notes\nContent-Type: text/plain; charset=utf-8\n\nLet's meet tomorrow for the project discussion.")
    (source / 'spam' / '00001.def456').write_bytes(b'From: offer@example.com\nSubject: Claim your prize now\nContent-Type: text/plain; charset=utf-8\n\nClick this link to claim your free prize today.')
    output = tmp_path / 'prepared.csv'
    old_argv = os.sys.argv
    try:
        os.sys.argv = ['prepare_corpus.py', '--source', str(source), '--output', str(output)]
        main()
    finally:
        os.sys.argv = old_argv
    import csv
    with output.open(newline='', encoding='utf-8') as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 2
    assert {row['label'] for row in rows} == {'SAFE', 'RESTRICTED'}
import pandas as pd
import pytest
from model_training.train_model import load_labeled_data

def test_training_scripts__test_training_data_maps_only_exact_supported_labels(tmp_path):
    csv_path = tmp_path / 'emails.csv'
    texts = [f'safe note {i}' for i in range(10)] + [f'restricted message {i}' for i in range(10)]
    labels = ['SAFE'] * 5 + ['HAM'] * 5 + ['RESTRICTED'] * 5 + ['SPAM'] * 5
    pd.DataFrame({'text': texts, 'label': labels}).to_csv(csv_path, index=False)
    loaded_texts, loaded_labels = load_labeled_data(csv_path)
    assert len(loaded_texts) == 20
    assert list(loaded_labels).count('SAFE') == 10
    assert list(loaded_labels).count('RESTRICTED') == 10

def test_training_scripts__test_training_data_rejects_missing_columns(tmp_path):
    csv_path = tmp_path / 'emails.csv'
    pd.DataFrame({'message': ['hello'], 'class': ['SAFE']}).to_csv(csv_path, index=False)
    with pytest.raises(SystemExit, match='missing required column'):
        load_labeled_data(csv_path)

def test_training_scripts__test_training_data_rejects_single_class(tmp_path):
    csv_path = tmp_path / 'emails.csv'
    pd.DataFrame({'text': [f'message {i}' for i in range(20)], 'label': ['SAFE'] * 20}).to_csv(csv_path, index=False)
    with pytest.raises(SystemExit, match='both SAFE and RESTRICTED'):
        load_labeled_data(csv_path)

def test_training_scripts__test_training_refuses_to_overwrite_existing_model_without_force(tmp_path):
    from model_training.train_model import ensure_output_available
    existing = tmp_path / 'existing.joblib'
    existing.write_bytes(b'keep this model')
    with pytest.raises(SystemExit, match='Refusing to overwrite'):
        ensure_output_available(existing)
    assert existing.read_bytes() == b'keep this model'

def test_training_scripts__test_training_allows_explicit_force_for_existing_model(tmp_path):
    from model_training.train_model import ensure_output_available
    existing = tmp_path / 'existing.joblib'
    existing.write_bytes(b'keep this model')
    ensure_output_available(existing, force=True)
    assert existing.read_bytes() == b'keep this model'
