import ipaddress
import re
from urllib.parse import urlparse

import idna
from bs4 import BeautifulSoup


# Find HTTP/HTTPS URLs written directly in email text.
URL_PATTERN = re.compile(
    r"""https?://[^\s<>"']+""",
    re.IGNORECASE,
)

# Remove common punctuation that may follow a URL in a sentence.
TRAILING_PUNCTUATION = ".,;:!?)]}"


def _validate_hostname(hostname: str) -> tuple[bool, bool]:
    """Validate a hostname and identify internationalized domain names."""
    if not hostname:
        return False, False

    try:
        ipaddress.ip_address(hostname)
        return True, False
    except ValueError:
        pass

    hostname = hostname.rstrip(".")

    if not hostname or len(hostname) > 253:
        return False, False

    labels = hostname.split(".")
    is_internationalized = False

    for label in labels:
        if not label or len(label) > 63:
            return False, is_internationalized

        if label.startswith("-") or label.endswith("-"):
            return False, is_internationalized

        if not re.fullmatch(r"[A-Za-z0-9-]+", label):
            is_internationalized = True

        if label.lower().startswith("xn--"):
            is_internationalized = True

        try:
            idna.encode(label, uts46=True, std3_rules=True)
        except idna.IDNAError:
            return False, is_internationalized

    return True, is_internationalized


def _inspect_single_url(
    href: str,
    display_text: str = "",
) -> list[dict]:
    """Inspect one URL and return any security findings."""
    findings = []

    href = href.strip()

    if not href:
        return findings

    parsed = urlparse(href)
    scheme = parsed.scheme.lower()

    # Preserve the existing rule for non-HTTP(S) hyperlinks.
    if scheme not in {"http", "https"}:
        findings.append(
            {
                "code": "NON_HTTP_LINK",
                "category": "SUSPICIOUS_LINK",
                "message": "A hyperlink uses a non-HTTP(S) scheme.",
            }
        )
        return findings

    try:
        hostname = parsed.hostname
        parsed.port  # Accessing this validates the port.
    except ValueError:
        findings.append(
            {
                "code": "MALFORMED_URL",
                "category": "SUSPICIOUS_LINK",
                "message": "A URL contains an invalid host or port.",
            }
        )
        return findings

    if not hostname or not parsed.netloc:
        findings.append(
            {
                "code": "MALFORMED_URL",
                "category": "SUSPICIOUS_LINK",
                "message": (
                    "An HTTP(S) hyperlink has a missing or invalid hostname."
                ),
            }
        )
        return findings

    if parsed.username is not None or parsed.password is not None:
        findings.append(
            {
                "code": "URL_CREDENTIALS_PRESENT",
                "category": "SUSPICIOUS_LINK",
                "message": (
                    "A URL contains embedded user information before its host."
                ),
            }
        )

    try:
        ipaddress.ip_address(hostname)
        is_ip_address = True
    except ValueError:
        is_ip_address = False

    if is_ip_address:
        findings.append(
            {
                "code": "IP_ADDRESS_LINK",
                "category": "SUSPICIOUS_LINK",
                "message": "A hyperlink uses an IP address as its host.",
            }
        )
    else:
        valid_hostname, is_internationalized = _validate_hostname(hostname)

        if not valid_hostname:
            findings.append(
                {
                    "code": "INVALID_HOSTNAME",
                    "category": "SUSPICIOUS_LINK",
                    "message": "A hyperlink contains a malformed hostname.",
                }
            )

        if is_internationalized:
            findings.append(
                {
                    "code": "IDN_HOSTNAME",
                    "category": "SUSPICIOUS_LINK",
                    "message": (
                        "A hyperlink uses Unicode or Punycode hostname "
                        "characters. Review the domain carefully."
                    ),
                }
            )

    # Compare the displayed URL with the actual destination.
    if display_text:
        displayed = display_text.lower().strip().rstrip("/")
        actual = href.lower().rstrip("/")

        if (
            displayed.startswith(("http://", "https://"))
            and displayed != actual
        ):
            findings.append(
                {
                    "code": "LINK_TEXT_MISMATCH",
                    "category": "SUSPICIOUS_LINK",
                    "message": (
                        "The displayed URL differs from the hyperlink target."
                    ),
                }
            )

    return findings


def inspect_urls(html: str) -> list[dict]:
    """
    Inspect hyperlinks and plain-text HTTP/HTTPS URLs in an email body.

    This function performs structural URL checks only. It does not establish
    whether a website is malicious or safe using live reputation data.
    """
    soup = BeautifulSoup(html or "", "html.parser")
    findings = []

    # Track inspected URLs to avoid duplicate findings when a URL appears
    # both as an href and as visible text.
    inspected_urls = set()

    # 1. Inspect HTML hyperlinks, including non-HTTP(S) schemes.
    for link in soup.find_all("a", href=True):
        href = link.get("href", "").strip()
        display_text = link.get_text(" ", strip=True)

        if not href:
            continue

        key = href

        if key in inspected_urls:
            continue

        inspected_urls.add(key)
        findings.extend(_inspect_single_url(href, display_text))

    # 2. Inspect URLs written directly in the email's visible text.
    visible_text = soup.get_text(" ", strip=True)

    for match in URL_PATTERN.finditer(visible_text):
        href = match.group(0).rstrip(TRAILING_PUNCTUATION)

        if not href:
            continue

        key = href

        if key in inspected_urls:
            continue

        inspected_urls.add(key)
        findings.extend(_inspect_single_url(href))

    return findings