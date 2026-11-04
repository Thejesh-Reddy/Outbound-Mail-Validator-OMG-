from typing import Literal
from pydantic import BaseModel, ConfigDict, Field


VerdictStatus = Literal["SAFE", "WARNING", "RESTRICTED"]


class InspectionIssue(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "MINOR", "LOW"]
    reason: str

class PopupAction(BaseModel):
    model_config = ConfigDict(extra="forbid")
    show: bool
    type: VerdictStatus
    title: str
    message: str
    actions: list[str] = Field(default_factory=list)


class AnalysisResponse(BaseModel):
    """Notify-facing response. Keep these keys aligned with the agreed contract."""
    model_config = ConfigDict(extra="forbid")

    status: VerdictStatus
    can_send: bool
    confidence_score: float = Field(ge=0, le=100)
    requires_acknowledgement: bool
    text: list[InspectionIssue] = Field(default_factory=list)
    URL: list[InspectionIssue] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    popup: PopupAction | None

