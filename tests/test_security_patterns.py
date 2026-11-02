
from text_validation.rule_checks import inspect_patterns
from html_inspection.html_inspection import inspect_html_content
from url_inspection.url_inspection import inspect_urls


tests = [
    {
        "name": "Lottery scam",
        "subject": "Congratulations! You Won a Lottery",
        "body": (
            "You have won a lottery prize. "
            "Pay an advance fee to claim your winnings."
        ),
        "should_detect": True,
    },
    {
        "name": "Credential phishing",
        "subject": "Urgent: Verify Your Account",
        "body": (
            "Your account will be suspended. "
            "Verify your password immediately."
        ),
        "should_detect": True,
    },
    {
        "name": "Urgent payment demand",
        "subject": "Urgent Payment Required",
        "body": (
            "Transfer the payment immediately to avoid "
            "account suspension."
        ),
        "should_detect": True,
    },
    {
        "name": "Fake prize offer",
        "subject": "Claim Your Free Prize",
        "body": (
            "You have been selected to receive a free prize. "
            "Pay a processing fee to claim it."
        ),
        "should_detect": True,
    },
    {
        "name": "Legitimate meeting invitation",
        "subject": "Team Meeting Tomorrow",
        "body": (
            "Hello team, our weekly meeting is scheduled "
            "for tomorrow at 10 AM. Please review the agenda."
        ),
        "should_detect": False,
    },
    {
        "name": "Legitimate invoice reminder",
        "subject": "Invoice Reminder",
        "body": (
            "This is a reminder that invoice INV-1024 is due "
            "on November 5. Please contact our accounts team "
            "if you have any questions."
        ),
        "should_detect": False,
    },
]


for test in tests:
    subject = test["subject"]
    body = test["body"]

    findings = []

    try:
        findings.extend(inspect_patterns(subject, body))
        findings.extend(inspect_html_content(subject, body))
        findings.extend(inspect_urls(body))

        codes = sorted(
            {
                item.get("code", "UNKNOWN")
                for item in findings
            }
        )

        detected = bool(findings)
        expected = test["should_detect"]
        passed = detected == expected

        print(
            f"{'PASS' if passed else 'CHECK'} | "
            f"{test['name']} | "
            f"Findings: {codes}"
        )

    except Exception as exc:
        print(f"ERROR | {test['name']} | {exc!r}")
