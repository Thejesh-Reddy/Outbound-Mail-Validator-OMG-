from typing import Literal
from pydantic import BaseModel, Field


class Finding(BaseModel):
    code: str
    category: str
    message: str


class AnalysisResponse(BaseModel):
    status: Literal["SAFE", "WARNING", "RESTRICTED"]
    can_send: bool
    confidence_score: float | None = Field(
        default=None, ge=0, le=100,
        description="Heuristic safety score (0-100), not a calibrated probability."
    )
    warning_required: bool = False
    requires_acknowledgement: bool = False
    patterns_detected: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    inspection_coverage: dict[str, str] = Field(default_factory=dict)
    model_version: str = "baseline-v1"
