"""Convert a locally extracted SpamAssassin-style corpus into OMG training CSV.

Expected source layout contains directories named ham and spam (case-insensitive),
with one raw RFC 822 email per file. This script does not download or execute email content.
"""
import argparse
import csv
from email import policy
from email.parser import BytesParser
from pathlib import Path
import re


def extract_body(raw: bytes) -> tuple[str, str]:
    message = BytesParser(policy=policy.default).parsebytes(raw)
    subject = str(message.get("subject", ""))
    parts = []
    if message.is_multipart():
        for part in message.walk():
            if part.get_content_maintype() != "text":
                continue
            if part.get_content_disposition() == "attachment":
                continue
            try:
                content = part.get_content()
            except (LookupError, UnicodeError, KeyError):
                payload = part.get_payload(decode=True) or b""
                content = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
            if part.get_content_subtype() == "html":
                from bs4 import BeautifulSoup
                content = BeautifulSoup(str(content), "html.parser").get_text(" ", strip=True)
            parts.append(str(content))
    else:
        try:
            content = message.get_content()
        except (LookupError, UnicodeError, KeyError):
            payload = message.get_payload(decode=True) or b""
            content = payload.decode(message.get_content_charset() or "utf-8", errors="replace")
        if message.get_content_subtype() == "html":
            from bs4 import BeautifulSoup
            content = BeautifulSoup(str(content), "html.parser").get_text(" ", strip=True)
        parts.append(str(content))
    body = " ".join(parts)
    # Keep subject and body only; exclude routing headers and attachment bytes.
    text = re.sub(r"\s+", " ", f"{subject} {body}").strip()
    return text, subject


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, help="Root of extracted corpus")
    parser.add_argument("--output", default="data/labeled_emails.csv")
    parser.add_argument("--min-chars", type=int, default=20)
    args = parser.parse_args()
    root = Path(args.source)
    if not root.is_dir():
        raise SystemExit(f"Corpus directory does not exist: {root}")

    records, seen = [], set()
    skipped = 0
    for path in root.rglob("*"):
        # SpamAssassin messages often use names like 00001.abc123 rather than
        # conventional .eml/.txt extensions. Treat every file under the
        # expected ham/spam directories as a candidate email message.
        if not path.is_file():
            continue
        parent_names = {p.name.lower() for p in path.parents}
        if "spam" in parent_names:
            label = "RESTRICTED"
        elif "ham" in parent_names:
            label = "SAFE"
        else:
            continue
        try:
            text, _ = extract_body(path.read_bytes())
        except Exception:
            skipped += 1
            continue
        if len(text) < args.min_chars:
            skipped += 1
            continue
        fingerprint = re.sub(r"\W+", " ", text.lower()).strip()
        if not fingerprint or fingerprint in seen:
            skipped += 1
            continue
        seen.add(fingerprint)
        records.append((text, label))

    counts = {label: sum(1 for _, current in records if current == label) for label in ("SAFE", "RESTRICTED")}
    if not records or not all(counts.values()):
        raise SystemExit(
            "Could not find both ham and spam messages. Expected folders named ham and spam "
            f"under {root}; found SAFE={counts['SAFE']}, RESTRICTED={counts['RESTRICTED']}."
        )
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["text", "label"])
        writer.writerows(records)
    print(f"Prepared {len(records)} unique emails: SAFE={counts['SAFE']}, RESTRICTED={counts['RESTRICTED']}")
    print(f"Skipped unreadable, short, or duplicate files: {skipped}")
    print(f"Wrote: {output.resolve()}")
    print("Review dataset provenance and label quality before training; this is not a threat-specific guarantee.")


if __name__ == "__main__":
    main()
