"""
OMG Validation Insights API.

The authenticated account ID must be populated by the application's verified
JWT authentication middleware as request.state.account_id. This module never
accepts account_id from query parameters or request bodies.
"""

from __future__ import annotations

import csv
import io
import re
from datetime import datetime, time, timedelta, timezone
from typing import Any

from bson import ObjectId
from bson.errors import InvalidId
from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from database import get_database

router = APIRouter(tags=["OMG Insights View"])

COLLECTION_NAME = "email_analysis"
MAX_PAGE_SIZE = 50
MAX_EXPORT_ROWS = 10000

ALLOWED_SORT_FIELDS = {
    "created_at": "created_at",
    "status": "status",
    "confidence_score": "confidence_score",
    "subject": "email.subject",
}
ALLOWED_COLUMNS = {
    "record_id": "Record ID",
    "subject": "Subject",
    "sender": "From",
    "content": "Content",
    "url": "URL",
    "attachment": "Attachment",
    "status": "Status",
    "confidence_score": "Confidence",
    "created_at": "Created At",
}


def _authenticated_account_id(request: Request) -> str:
    """Read identity set by trusted JWT middleware; fail closed otherwise."""
    account_id = getattr(request.state, "account_id", None)

    if not account_id:
        user = getattr(request.state, "user", None)
        if isinstance(user, dict):
            account_id = user.get("account_id") or user.get("id") or user.get("_id")
        elif user is not None:
            account_id = (
                getattr(user, "account_id", None)
                or getattr(user, "id", None)
                or getattr(user, "_id", None)
            )

    if not account_id:
        raise HTTPException(
            status_code=401,
            detail=(
                "JWT authentication is required. The authentication "
                "middleware must set request.state.account_id."
            ),
        )

    return str(account_id)


def _collection():
    return get_database()[COLLECTION_NAME]


def _date_bounds(
    date_filter: str | None,
    from_date: str | None,
    to_date: str | None,
    tz_offset_minutes: int = 0,
) -> tuple[datetime | None, datetime | None]:
    # JavaScript getTimezoneOffset() is UTC minus local time.
    local_tz = timezone(timedelta(minutes=-tz_offset_minutes))
    now = datetime.now(timezone.utc)
    local_now = now.astimezone(local_tz)
    today = local_now.date()

    if not date_filter or date_filter == "all":
        if from_date or to_date:
            date_filter = "custom"
        else:
            return None, None

    if date_filter == "today":
        start_local = datetime.combine(today, time.min, tzinfo=local_tz)
        end_local = start_local + timedelta(days=1)
        return start_local.astimezone(timezone.utc), end_local.astimezone(timezone.utc)

    if date_filter == "yesterday":
        day = today - timedelta(days=1)
        start_local = datetime.combine(day, time.min, tzinfo=local_tz)
        end_local = start_local + timedelta(days=1)
        return start_local.astimezone(timezone.utc), end_local.astimezone(timezone.utc)

    if date_filter == "last_7_days":
        start_local = datetime.combine(today - timedelta(days=6), time.min, tzinfo=local_tz)
        return start_local.astimezone(timezone.utc), now + timedelta(microseconds=1)

    if date_filter == "custom":
        if not from_date and not to_date:
            raise HTTPException(400, "Custom date range requires from_date or to_date")
        try:
            start = (
                datetime.combine(datetime.strptime(from_date, "%Y-%m-%d").date(),
                                 time.min, tzinfo=local_tz).astimezone(timezone.utc)
                if from_date else None
            )
            # Exclusive upper bound includes the complete local to_date.
            end = (
                (datetime.combine(datetime.strptime(to_date, "%Y-%m-%d").date(),
                                  time.min, tzinfo=local_tz) + timedelta(days=1))
                .astimezone(timezone.utc)
                if to_date else None
            )
        except ValueError:
            raise HTTPException(400, "Dates must use YYYY-MM-DD format")
        if start and end and start >= end:
            raise HTTPException(400, "from_date must be on or before to_date")
        return start, end

    raise HTTPException(400, "Unsupported date_filter")


def _build_query(
    account_id: str,
    search: str | None,
    status: str | None,
    date_filter: str | None,
    from_date: str | None,
    to_date: str | None,
    tz_offset_minutes: int = 0,
) -> dict[str, Any]:
    query: dict[str, Any] = {"account_id": account_id}

    if status and status.lower() != "all":
        normalized = status.upper()
        if normalized not in {"SAFE", "WARNING", "RESTRICTED"}:
            raise HTTPException(400, "status must be SAFE, WARNING, RESTRICTED, or all")
        query["status"] = normalized

    if search and search.strip():
        term = search.strip()[:200]
        clauses: list[dict[str, Any]] = [
            {"email.subject": {"$regex": re.escape(term), "$options": "i"}},
            {"email.from": {"$regex": re.escape(term), "$options": "i"}},
            {"email.to": {"$regex": re.escape(term), "$options": "i"}},
            {"email.body": {"$regex": re.escape(term), "$options": "i"}},
            {"user_email": {"$regex": re.escape(term), "$options": "i"}},
            {"request_id": {"$regex": re.escape(term), "$options": "i"}},
        ]
        try:
            clauses.append({"_id": ObjectId(term)})
        except (InvalidId, TypeError):
            pass
        query["$or"] = clauses

    if not -840 <= tz_offset_minutes <= 840:
        raise HTTPException(400, "tz_offset_minutes must be between -840 and 840")
    start, end = _date_bounds(date_filter, from_date, to_date, tz_offset_minutes)
    if start or end:
        date_query: dict[str, Any] = {}
        if start:
            date_query["$gte"] = start
        if end:
            date_query["$lt"] = end
        query["created_at"] = date_query

    return query


def _serialize_record(record: dict[str, Any]) -> dict[str, Any]:
    record["_id"] = str(record["_id"])
    # Internal account identifier is used for isolation, not needed in the UI.
    record.pop("account_id", None)
    return record


def _parse_columns(columns: str | None) -> list[str]:
    if not columns:
        return list(ALLOWED_COLUMNS)
    selected = [item.strip() for item in columns.split(",") if item.strip()]
    unknown = [item for item in selected if item not in ALLOWED_COLUMNS]
    if unknown:
        raise HTTPException(400, f"Unsupported columns: {', '.join(unknown)}")
    return selected or list(ALLOWED_COLUMNS)


def _export_rows(query: dict[str, Any], sort_field: str, sort_order: str,
                 selected_columns: list[str]) -> list[dict[str, Any]]:
    direction = 1 if sort_order == "asc" else -1
    cursor = _collection().find(query).sort(sort_field, direction).limit(MAX_EXPORT_ROWS + 1)
    records = list(cursor)
    if len(records) > MAX_EXPORT_ROWS:
        raise HTTPException(
            413,
            f"Export exceeds {MAX_EXPORT_ROWS} records. Narrow your filters and try again.",
        )

    rows = []
    for raw in records:
        rec = _serialize_record(raw)
        email = rec.get("email") if isinstance(rec.get("email"), dict) else {}
        content_value = email.get("body") or rec.get("content") or rec.get("text", "")
        url_value = rec.get("url", "")
        attachment_value = rec.get("attachments", rec.get("attachment", ""))
        def export_value(value: Any) -> str:
            if value is None:
                return ""
            if isinstance(value, (dict, list)):
                import json
                return json.dumps(value, ensure_ascii=False, default=str)
            return str(value)
        row = {
            "record_id": rec.get("_id", ""),
            "subject": email.get("subject") or rec.get("subject") or "",
            "sender": email.get("from") or rec.get("user_email") or "",
            "content": export_value(content_value),
            "url": export_value(url_value),
            "attachment": export_value(attachment_value),
            "status": rec.get("status") or email.get("status") or "",
            "confidence_score": rec.get("confidence_score", email.get("confidence_score", "")),
            "created_at": rec.get("created_at").isoformat() if isinstance(rec.get("created_at"), datetime) else str(rec.get("created_at", "")),
        }
        rows.append({key: row.get(key, "") for key in selected_columns})
    return rows


@router.get("/omg_insights_view", operation_id="omg_insights_view")
def get_json_view(
    request: Request,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=MAX_PAGE_SIZE),
    search: str | None = None,
    status: str | None = None,
    date_filter: str | None = "all",
    from_date: str | None = None,
    to_date: str | None = None,
    tz_offset_minutes: int = Query(0, ge=-840, le=840),
    sort_by: str = "created_at",
    sort_order: str = "desc",
    columns: str | None = None,
):
    """Return a paginated validation insights view for the authenticated account."""
    account_id = _authenticated_account_id(request)

    if sort_by not in ALLOWED_SORT_FIELDS:
        raise HTTPException(400, f"sort_by must be one of: {', '.join(ALLOWED_SORT_FIELDS)}")
    if sort_order not in {"asc", "desc"}:
        raise HTTPException(400, "sort_order must be asc or desc")

    selected_columns = _parse_columns(columns)
    query = _build_query(account_id, search, status, date_filter, from_date, to_date, tz_offset_minutes)
    collection = _collection()
    print("\n========== OMG INSIGHTS DEBUG ==========")
    print("Authenticated Account ID:", repr(account_id))
    print("Database:", collection.database.name)
    print("Collection:", collection.name)
    print("Total documents:", collection.count_documents({}))
    print("Matching account documents:",
        collection.count_documents({"account_id": account_id}))
    print("========================================\n")

    total_records = collection.count_documents(query)
    direction = 1 if sort_order == "asc" else -1
    cursor = (
        collection.find(query)
        .sort(ALLOWED_SORT_FIELDS[sort_by], direction)
        .skip((page - 1) * page_size)
        .limit(page_size)
    )
    records = [_serialize_record(item) for item in cursor]

    summary_query = _build_query(
        account_id, search, None, date_filter, from_date, to_date, tz_offset_minutes
    )
    status_counts = {"SAFE": 0, "WARNING": 0, "RESTRICTED": 0}
    for item in collection.aggregate([
        {"$match": summary_query},
        {"$group": {"_id": "$status", "count": {"$sum": 1}}},
    ]):
        if item.get("_id") in status_counts:
            status_counts[item["_id"]] = item.get("count", 0)

    return {
        "records": records,
        "status_counts": status_counts,
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total_records": total_records,
            "total_pages": (total_records + page_size - 1) // page_size,
            "has_next": page * page_size < total_records,
            "has_previous": page > 1,
        },
        "selected_columns": selected_columns,
        "filters": {
            "search": search,
            "status": status or "all",
            "date_filter": date_filter or "all",
            "from_date": from_date,
            "to_date": to_date,
            "sort_by": sort_by,
            "sort_order": sort_order,
        },
    }


@router.get("/omg_insights_view/export")
def export_json_view(
    request: Request,
    format: str = Query("csv", pattern="^(csv|xlsx)$"),
    search: str | None = None,
    status: str | None = None,
    date_filter: str | None = "all",
    from_date: str | None = None,
    to_date: str | None = None,
    tz_offset_minutes: int = Query(0, ge=-840, le=840),
    sort_by: str = "created_at",
    sort_order: str = "desc",
    columns: str | None = None,
):
    """Export filtered validation insights; account scoping is identical to the table API."""
    account_id = _authenticated_account_id(request)
    if sort_by not in ALLOWED_SORT_FIELDS:
        raise HTTPException(400, f"sort_by must be one of: {', '.join(ALLOWED_SORT_FIELDS)}")
    if sort_order not in {"asc", "desc"}:
        raise HTTPException(400, "sort_order must be asc or desc")

    selected_columns = _parse_columns(columns)
    query = _build_query(account_id, search, status, date_filter, from_date, to_date, tz_offset_minutes)
    rows = _export_rows(query, ALLOWED_SORT_FIELDS[sort_by], sort_order, selected_columns)
    headers = [ALLOWED_COLUMNS[key] for key in selected_columns]

    if format == "csv":
        stream = io.StringIO()
        writer = csv.writer(stream)
        writer.writerow(headers)
        for row in rows:
            writer.writerow([row.get(key, "") for key in selected_columns])
        content = io.BytesIO(stream.getvalue().encode("utf-8-sig"))
        return StreamingResponse(
            content,
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": 'attachment; filename="omg_validation_insights.csv"'},
        )

    try:
        from openpyxl import Workbook
    except ImportError:
        raise HTTPException(501, "Excel export requires openpyxl; install project requirements")

    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Validation Insights"
    sheet.append(headers)
    for row in rows:
        sheet.append([row.get(key, "") for key in selected_columns])
    sheet.freeze_panes = "A2"
    sheet.auto_filter.ref = sheet.dimensions
    for column_cells in sheet.columns:
        letter = column_cells[0].column_letter
        max_length = max((len(str(cell.value or "")) for cell in column_cells), default=10)
        sheet.column_dimensions[letter].width = min(max(max_length + 2, 12), 48)
    output = io.BytesIO()
    workbook.save(output)
    output.seek(0)
    return StreamingResponse(
        output,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": 'attachment; filename="omg_validation_insights.xlsx"'},
    )


@router.get("/omg_insights_view/{record_id}")
def get_json_view_record(request: Request, record_id: str):
    """Return the complete validation document for one owned record."""
    account_id = _authenticated_account_id(request)
    try:
        object_id = ObjectId(record_id)
    except (InvalidId, TypeError):
        raise HTTPException(400, "Invalid record ID")

    record = _collection().find_one({"_id": object_id, "account_id": account_id})
    if not record:
        raise HTTPException(404, "Validation record not found")
    return {"record": _serialize_record(record)}
