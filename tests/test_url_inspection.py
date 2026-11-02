
from url_inspection.url_inspection import inspect_urls

tests = [
    (
        "Plain-text IP URL",
        "Verify your account at http://192.168.1.10/login immediately.",
        "IP_ADDRESS_LINK",
    ),
    (
        "HTML IP hyperlink",
        '<a href="http://192.168.1.10/login">Verify account</a>',
        "IP_ADDRESS_LINK",
    ),
    (
        "Mismatched displayed URL",
        '<a href="https://evil.example/login">https://trusted.example</a>',
        "LINK_TEXT_MISMATCH",
    ),
    (
        "Non-HTTP hyperlink",
        '<a href="javascript:alert(1)">Click</a>',
        "NON_HTTP_LINK",
    ),
    (
        "Legitimate email without links",
        "<p>The team meeting is scheduled for tomorrow at 10 AM.</p>",
        None,
    ),
]

for name, body, expected_code in tests:
    findings = inspect_urls(body)
    detected_codes = {finding["code"] for finding in findings}

    if expected_code is None:
        passed = not findings
    else:
        passed = expected_code in detected_codes

    print(
        f"{'PASS' if passed else 'FAIL'} | {name} | "
        f"Detected: {sorted(detected_codes)}"
    )
