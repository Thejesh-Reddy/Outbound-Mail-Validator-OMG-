from scripts.prepare_corpus import extract_body


def test_extract_body_keeps_subject_and_body_and_ignores_headers():
    raw = b"From: sender@example.com\nSubject: Account notice\nContent-Type: text/plain; charset=utf-8\n\nPlease review your account."
    text, subject = extract_body(raw)
    assert subject == "Account notice"
    assert "Account notice" in text
    assert "Please review your account." in text
    assert "sender@example.com" not in text


def test_extract_body_handles_html():
    raw = b"Subject: Offer\nContent-Type: text/html; charset=utf-8\n\n<html><body><p>Limited offer</p></body></html>"
    text, _ = extract_body(raw)
    assert "Limited offer" in text
    assert "<p>" not in text


def test_corpus_files_with_nonstandard_suffix_are_included(tmp_path):
    from scripts.prepare_corpus import main
    import os

    source = tmp_path / "corpus"
    (source / "ham").mkdir(parents=True)
    (source / "spam").mkdir(parents=True)
    (source / "ham" / "00001.abc123").write_bytes(
        b"From: friend@example.com\nSubject: Meeting notes\nContent-Type: text/plain; charset=utf-8\n\nLet's meet tomorrow for the project discussion."
    )
    (source / "spam" / "00001.def456").write_bytes(
        b"From: offer@example.com\nSubject: Claim your prize now\nContent-Type: text/plain; charset=utf-8\n\nClick this link to claim your free prize today."
    )
    output = tmp_path / "prepared.csv"
    old_argv = os.sys.argv
    try:
        os.sys.argv = ["prepare_corpus.py", "--source", str(source), "--output", str(output)]
        main()
    finally:
        os.sys.argv = old_argv
    import csv
    with output.open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 2
    assert {row["label"] for row in rows} == {"SAFE", "RESTRICTED"}
