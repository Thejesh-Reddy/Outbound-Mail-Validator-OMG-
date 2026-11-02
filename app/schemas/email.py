import re
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator

_EMAIL_LIKE = re.compile(r"^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$")


class EmailRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    channel: Literal["email"] = "email"
    subject: str = Field(..., min_length=1, max_length=998)
    html: str = Field(..., min_length=1, max_length=1_000_000)
    recipients: list[str] = Field(..., min_length=1, max_length=100)
    attachments: list[dict] = Field(default_factory=list, max_length=50)

    @field_validator("subject")
    @classmethod
    def subject_not_whitespace(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("subject must not be whitespace only")
        return value.strip()

    @field_validator("recipients")
    @classmethod
    def validate_recipients(cls, values: list[str]) -> list[str]:
        cleaned = []
        for value in values:
            if not isinstance(value, str) or not _EMAIL_LIKE.fullmatch(value.strip()):
                raise ValueError("each recipient must be a valid email address")
            cleaned.append(value.strip())
        return cleaned
