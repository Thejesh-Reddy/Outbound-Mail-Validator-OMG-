
from app.schemas.email import EmailRequest
from app.pipeline.orchestrator import analyze_email


test_cases = [
    {
        "name": "Suspicious plain-text IP URL",
        "subject": "Urgent: Verify Your Account",
        "html": (
            "Your mailbox will be disabled today. "
            "Verify your credentials at "
            "http://192.168.1.10/login immediately."
        ),
        "attachments": [],
        "expected": "RESTRICTED",
    },
    {
        "name": "Suspicious HTML IP hyperlink",
        "subject": "Account Verification Required",
        "html": (
            '<p>Verify your account immediately.</p>'
            '<a href="http://192.168.1.10/login">'
            "Verify Account</a>"
        ),
        "attachments": [],
        "expected": "RESTRICTED",
    },
    {
        "name": "Lottery scam",
        "subject": "Congratulations! You Won a Lottery",
        "html": (
            "You have won a lottery prize. "
            "Pay an advance fee to claim your winnings."
        ),
        "attachments": [],
        "expected": "RESTRICTED",
    },
    {
        "name": "Credential phishing",
        "subject": "Urgent: Verify Your Account",
        "html": (
            "Your account will be suspended. "
            "Verify your password immediately."
        ),
        "attachments": [],
        "expected": "RESTRICTED",
    },
    {
        "name": "Urgent payment demand",
        "subject": "Urgent Payment Required",
        "html": (
            "Transfer the payment immediately to avoid "
            "account suspension."
        ),
        "attachments": [],
        "expected": "RESTRICTED",
    },
    {
        "name": "Legitimate meeting invitation",
        "subject": "Team Meeting Tomorrow",
        "html": (
            "Hello team, our weekly meeting is scheduled "
            "for tomorrow at 10 AM. Please review the agenda."
        ),
        "attachments": [],
        "expected": "SAFE",
    },
    {
        "name": "Email containing attachment",
        "subject": "Project Report",
        "html": "Please find the requested project report attached.",
        "attachments": [{"filename": "report.pdf"}],
        "expected": "RESTRICTED",
    },
]


for test in test_cases:
    print(f"\nTesting: {test['name']}")

    try:
        email = EmailRequest(
            channel="email",
            subject=test["subject"],
            html=test["html"],
            recipients=["test@example.com"],
            attachments=test["attachments"],
        )

        result = analyze_email(email)

        if hasattr(result, "model_dump"):
            result = result.model_dump()
        elif not isinstance(result, dict):
            result = vars(result)

        actual = result.get("status")
        can_send = result.get("can_send")

        passed = (
            actual == test["expected"]
            and can_send is (test["expected"] == "SAFE")
        )

        print(f"Expected verdict: {test['expected']}")
        print(f"Actual verdict:   {actual}")
        print(f"Can send:         {can_send}")
        print(f"Result:           {'PASS' if passed else 'FAIL'}")

        if not passed:
            print("Response:", result)

    except Exception as exc:
        print("PIPELINE TEST ERROR:", repr(exc))
