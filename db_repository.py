"""Persistence for the exact three-table OMG MySQL schema."""
from datetime import datetime, timezone
from decimal import Decimal
from sqlalchemy import func, or_, text
from database import AnalysisRecord, SessionLocal, utc_now_naive


def _record_to_dict(r):
    return {
        "_id": r.id, "transaction_id": r.transaction_id,
        "status": r.status, "confidence_score": float(r.confidence_score),
        "message": r.message, "text_result": r.text_result,
        "url_result": r.url_result, "attachment_result": r.attachment_result,
        "error_details": r.error_details, "popup": r.popup,
    }


def save_analysis(account_id: str, analysis_result: dict, email_data=None,
                  request_id=None, user_email=None):
    """Persist formatted API result; account and email content are not in the specified table."""
    tx = analysis_result["transaction"]
    sm = analysis_result["summary"]
    with SessionLocal() as db:
        # Allocate the daily sequence and save under the SAME connection lock.
        # This prevents duplicate transaction IDs across concurrent workers.
        locked = db.execute(text("SELECT GET_LOCK('omg_transaction_sequence', 10)")).scalar()
        if locked != 1:
            raise RuntimeError("Could not acquire transaction ID lock")
        try:
            today = datetime.now(timezone.utc).strftime("%Y%m%d")
            prefix = f"OMG-{today}-"
            last = db.query(func.max(AnalysisRecord.transaction_id)).filter(
                AnalysisRecord.transaction_id.like(prefix + "%")
            ).scalar()
            number = int(last.rsplit("-", 1)[-1]) + 1 if last else 1
            tx["transaction_id"] = f"{prefix}{number:06d}"
            r = AnalysisRecord(
                transaction_id=tx["transaction_id"],
                status=tx["status"].upper(),
                confidence_score=Decimal(str(tx["confidence_score"])),
                message=tx["message"][:100],
                text_result=sm["text"], url_result=sm["url"],
                attachment_result=sm["attachments"],
                error_details=analysis_result.get("_error_details"),
                popup=sm["popup"],
            )
            db.add(r)
            db.commit()
            return {"saved": True, "record_id": r.id}
        finally:
            db.execute(text("SELECT RELEASE_LOCK('omg_transaction_sequence')"))



def get_account_history(account_id: str, limit: int = 50):
    raise NotImplementedError("Account-specific history requires account_id in email_analysis")


def get_analysis_by_id(account_id: str, record_id):
    raise NotImplementedError("Account-specific lookup requires account_id in email_analysis")


def query_analysis_records(account_id=None, status=None, start_at=None,
                           end_before=None, search=None, record_id=None,
                           sort_by="status", descending=True,
                           offset=0, limit=None):
    if account_id:
        raise ValueError("Account filtering requires an account_id column")
    conditions = []
    if status: conditions.append(AnalysisRecord.status == status)
    if record_id: conditions.append(AnalysisRecord.id == record_id)
    if search:
        pattern = "%" + search.replace("%", "\\%").replace("_", "\\_") + "%"
        conditions.append(or_(AnalysisRecord.transaction_id.like(pattern),
                              AnalysisRecord.message.like(pattern)))
    # The exact requested schema has no created_at field in email_analysis.
    if start_at or end_before:
        raise ValueError("Date filtering requires created_at in email_analysis")
    columns = {"status": AnalysisRecord.status,
               "confidence_score": AnalysisRecord.confidence_score,
               "transaction_id": AnalysisRecord.transaction_id,
               "created_at": AnalysisRecord.transaction_id}
    with SessionLocal() as db:
        total = db.query(func.count(AnalysisRecord.id)).filter(*conditions).scalar()
        col = columns.get(sort_by, AnalysisRecord.transaction_id)
        q = db.query(AnalysisRecord).filter(*conditions).order_by(
            col.desc() if descending else col.asc())
        if limit is not None: q = q.offset(offset).limit(limit)
        return total, [_record_to_dict(r) for r in q.all()]


def query_unique_analysis_users(**kwargs):
    raise NotImplementedError("User history requires user_email in email_analysis")
