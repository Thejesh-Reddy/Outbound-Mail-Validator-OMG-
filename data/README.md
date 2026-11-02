# OMG data

`labeled_emails.csv` is generated locally and is intentionally not bundled. Do not commit private or company email.

## Preparing a public raw-email corpus

1. Download a corpus from its official source and review its license/provenance.
2. Extract it so raw email files are located beneath directories named `ham` and `spam`.
3. From the project root run:

```powershell
python scripts/prepare_corpus.py --source "C:\path\to\extracted\corpus" --output data/labeled_emails.csv
```

The script labels `ham` as `SAFE` and `spam` as `RESTRICTED`, extracts subject and text body, excludes attachment payloads, skips duplicates and short/unreadable messages, and reports class counts. Manually review the corpus layout and sample records before training. It does not infer phishing, malicious attachments, inappropriate content, or whether a message is safe to send in your organization's context.

Suggested starter corpus: Rspamd's test email corpus release, based on the SpamAssassin public corpus. Its release page states it contains 1,000 messages (300 spam, 700 ham) and describes it as public domain/freely redistributable: https://github.com/rspamd/rspamd-test-corpus/releases. This is a small starter dataset, not sufficient by itself to establish production performance.
