"""Small local smoke/load test; not a substitute for production load testing."""
import argparse
import time
import httpx

parser = argparse.ArgumentParser()
parser.add_argument("--url", default="http://127.0.0.1:8000/api/v1/analyze")
parser.add_argument("--requests", type=int, default=25)
args = parser.parse_args()
payload = {"channel": "email", "subject": "Project meeting", "html": "<p>Meeting at 10 AM.</p>",
           "recipients": ["recipient@example.com"], "attachments": []}
start = time.perf_counter()
with httpx.Client(timeout=10) as client:
    for i in range(args.requests):
        response = client.post(args.url, json=payload)
        response.raise_for_status()
elapsed = time.perf_counter() - start
print(f"Requests: {args.requests}; total_seconds: {elapsed:.3f}; requests_per_second: {args.requests / elapsed:.2f}")
