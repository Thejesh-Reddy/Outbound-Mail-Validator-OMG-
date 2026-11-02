"""Fail-closed attachment scanning using the local ClamAV clamscan CLI.

The API accepts attachment bytes as base64 (`content_base64`). Client-supplied
filesystem paths are never opened. ClamAV is an optional external dependency;
if it is not installed/configured, attachments remain blocked.
"""
from __future__ import annotations

import base64
import binascii
import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Protocol


MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024
MAX_TOTAL_ATTACHMENT_BYTES = 45 * 1024 * 1024


class AttachmentScanner(Protocol):
    def scan(self, attachments: list[dict]) -> dict: ...


@dataclass
class ClamAVScanner:
    executable: str = "clamscan"
    timeout_seconds: int = 30

    def scan(self, attachments: list[dict]) -> dict:
        findings: list[dict] = []
        total_bytes = 0
        for index, attachment in enumerate(attachments):
            if not isinstance(attachment, dict):
                return _failure("ATTACHMENT_INVALID", "An attachment entry is invalid.")
            encoded = attachment.get("content_base64")
            if not isinstance(encoded, str) or not encoded:
                return _failure(
                    "ATTACHMENT_CONTENT_MISSING",
                    "Attachment content is required for malware scanning; metadata alone is insufficient.",
                )
            try:
                content = base64.b64decode(encoded, validate=True)
            except (binascii.Error, ValueError):
                return _failure("ATTACHMENT_ENCODING_INVALID", "Attachment content is not valid base64.")
            if not content:
                return _failure("ATTACHMENT_EMPTY", "Empty attachments are not accepted for scanning.")
            if len(content) > MAX_ATTACHMENT_BYTES:
                return _failure("ATTACHMENT_TOO_LARGE", "An attachment exceeds the 25 MiB scanning limit.")
            total_bytes += len(content)
            if total_bytes > MAX_TOTAL_ATTACHMENT_BYTES:
                return _failure("ATTACHMENTS_TOTAL_TOO_LARGE", "Combined attachments exceed the 45 MiB scanning limit.")

            try:
                completed = subprocess.run(
                    [self.executable, "--no-summary", "-"],
                    input=content,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=self.timeout_seconds,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                return _failure("ATTACHMENT_SCAN_TIMEOUT", "ClamAV did not finish scanning an attachment in time.")
            except OSError:
                return _failure("ATTACHMENT_SCANNER_ERROR", "The configured ClamAV scanner could not be started.")

            output = (completed.stdout + completed.stderr).decode("utf-8", errors="replace")
            if completed.returncode == 1 and "FOUND" in output:
                findings.append({
                    "code": "ATTACHMENT_MALWARE_DETECTED",
                    "category": "MALWARE",
                    "message": f"ClamAV detected malware in attachment {index + 1}.",
                })
            elif completed.returncode != 0:
                return _failure("ATTACHMENT_SCAN_INCOMPLETE", "ClamAV could not complete the attachment scan.")

        return {
            "completed": True,
            "safe": not findings,
            "findings": findings,
            "status": "clamav_scan_complete",
        }


def _failure(code: str, message: str) -> dict:
    return {"completed": False, "safe": False, "findings": [{
        "code": code,
        "category": "INSPECTION_FAILURE",
        "message": message,
    }]}


def configured_scanner() -> AttachmentScanner | None:
    configured = os.getenv("OMG_CLAMSCAN_PATH", "").strip()
    executable = configured or shutil.which("clamscan")
    if not executable:
        return None
    try:
        timeout = max(1, min(120, int(os.getenv("OMG_ATTACHMENT_SCAN_TIMEOUT", "30"))))
    except ValueError:
        timeout = 30
    return ClamAVScanner(executable=executable, timeout_seconds=timeout)


def scan_attachments(
    attachments: list[dict],
    scanner: AttachmentScanner | None = None,
) -> dict:
    """Scan attachments, blocking by default if a scanner is unavailable."""
    if not attachments:
        return {
            "completed": True,
            "safe": True,
            "findings": [],
            "status": "not_applicable_no_attachments",
        }
    if scanner is None:
        return _failure(
            "ATTACHMENT_SCAN_UNAVAILABLE",
            "ClamAV is not configured; attachments cannot be released without malware scanning.",
        )
    try:
        result = scanner.scan(attachments)
        if (
            not isinstance(result, dict)
            or result.get("completed") is not True
            or not isinstance(result.get("safe"), bool)
            or not isinstance(result.get("findings"), list)
        ):
            return _failure("ATTACHMENT_SCAN_INCOMPLETE", "Attachment inspection returned an invalid result.")
        if result["safe"] is False and not result["findings"]:
            return _failure("ATTACHMENT_SCAN_INCOMPLETE", "Attachment scanner reported unsafe content without a finding.")
        return result
    except Exception:
        return _failure("ATTACHMENT_SCAN_ERROR", "The attachment scanner failed unexpectedly.")
