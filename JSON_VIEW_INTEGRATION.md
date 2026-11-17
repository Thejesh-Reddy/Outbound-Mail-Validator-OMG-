# OMG Validation Insights integration notes

## Files

- `json_view.py` — FastAPI router for account-scoped validation insights.
- `frontend/history.html` — standalone Validation Insights page.
- `app.py` — mounts the API router and serves the page at `/json_view`.

## Routes

- `GET /json_view` — Validation Insights frontend page.
- `GET /history` — compatibility alias for the frontend page.
- `GET /api/v1/omg_insights_view` — paginated validation insights data.
- `GET /api/v1/omg_insights_view/{record_id}` — complete stored validation document.
- `GET /api/v1/omg_insights_view/export?format=csv` — CSV export.
- `GET /api/v1/omg_insights_view/export?format=xlsx` — Excel export.

The API prefix follows `OMG_API_PREFIX` in the existing application settings (normally `/api/v1`).

## Authentication integration

The page no longer asks for a JWT token manually. It sends same-origin requests with browser credentials (`credentials: include`). The application's existing authenticated session/middleware must identify the caller and set `request.state.account_id` to a verified account identifier. If that identity is missing, the API returns HTTP 401. The API never accepts an account ID from the browser.

The uploaded application currently uses API-key authentication for `/api/v1/analyze` and saves analysis with a fixed `api-key-client` account ID. This JSON endpoint therefore still requires the application's authenticated identity integration before account-scoped records can be returned. This change does not modify the existing analysis/authentication flow.

## Filters and display

The page includes status and date filters, ascending/descending ordering, pagination (maximum 50 rows per page), column selection, complete JSON viewing by clicking a record ID, and CSV/XLSX export. The visible columns include Content, URL, and Attachment instead of Recipients. The search control and sort-field dropdown have been removed from the page.


## Insights button and account handoff

The Validation page now includes an **Insights** button that opens `/json_view`.
The Insights frontend sends same-origin cookies with its API requests. The API
continues to require a trusted identity on `request.state.account_id`; it never
accepts an account ID supplied in a query parameter or request body.

The current merged project does not contain the application's login/JWT
authentication implementation. The host login middleware must therefore be
integrated to set `request.state.account_id` after verifying the user's session
or JWT. Once that is connected, new validation records use that authenticated
account ID. Until then, the existing API-key flow retains the legacy
`api-key-client` account label to avoid changing current validation behavior;
those legacy records will not appear in an individual authenticated account's
Insights view.


## Temporary local testing with a specific account

To test the Validation Insights frontend before the application's real JWT
authentication middleware is integrated, enable the development-only identity
override in your local `.env` file (never commit this setting):

```dotenv
OMG_ENV=development
OMG_ENVIRONMENT=development
OMG_INSIGHTS_DEV_TEST_MODE=true
OMG_INSIGHTS_TEST_ACCOUNT_ID=6afaebf98bd7a5b38f40dee6
```

This override applies only to `/api/v1/analyze` and `/api/v1/omg_insights_view`
(including its export/record subroutes), only when the server is not in production,
and only when the request comes from a loopback client (`127.0.0.1` or `::1`). The account ID is read from
server-side environment configuration; the browser cannot choose an account
ID. It allows the frontend to read existing `email_analysis` documents whose
`account_id` equals the string form of the selected user's MongoDB `_id`, and
new local `/analyze` validation records are saved under that same test account.

Keep `OMG_INSIGHTS_DEV_TEST_MODE=false` (or remove both test variables) when
finished. This is a local frontend testing aid, not production authentication.
The production integration must set `request.state.account_id` from a verified
login session/JWT and must save new validation records with that same account ID.
