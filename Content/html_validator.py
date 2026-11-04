"""Structural HTML inspection for outgoing email content."""
import re
from bs4 import BeautifulSoup


def inspect_html_content(subject: str, html_content: str) -> list[dict]:
    """Identify hidden content and credential-capture form structures."""
    findings: list[dict] = []
    soup = BeautifulSoup(html_content or "", "html.parser")

    for element in soup.find_all(True):
        style = (element.get("style") or "").lower()
        aria_hidden = (element.get("aria-hidden") or "").lower()
        hidden = (
            element.has_attr("hidden")
            or aria_hidden == "true"
            or bool(re.search(r"display\s*:\s*none", style))
            or bool(re.search(r"visibility\s*:\s*hidden", style))
            or bool(re.search(r"opacity\s*:\s*0(?:\s*;|\s*$)", style))
        )
        hidden_text = element.get_text(" ", strip=True)
        if hidden and hidden_text:
            findings.append({
                "code": "HIDDEN_HTML_TEXT",
                "category": "SUSPICIOUS_CONTENT",
                "message": "An HTML element contains text but is marked as hidden.",
            })
            break

    # A password field in an outgoing email form is unusual and requires review.
    for form in soup.find_all("form"):
        if form.find("input", attrs={"type": re.compile(r"^password$", re.I)}):
            findings.append({
                "code": "HTML_PASSWORD_CAPTURE_FORM",
                "category": "CREDENTIAL_THEFT",
                "message": "The email HTML contains a form with a password input.",
            })
            break

    return findings
