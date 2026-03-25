from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field, PositiveInt, ValidationError, field_validator


ACCEPT_LANGUAGE_PATTERN = re.compile(
    r"^[A-Za-z]{1,8}(?:-[A-Za-z0-9]{1,8})?"
    r"(?:\s*,\s*[A-Za-z]{1,8}(?:-[A-Za-z0-9]{1,8})?(?:\s*;\s*q=\d(?:\.\d{1,3})?)?)*$"
)


class UserCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    email: EmailStr
    age: PositiveInt | None = None
    is_subscribed: bool | None = None

    model_config = ConfigDict(str_strip_whitespace=True)


class Product(BaseModel):
    product_id: int
    name: str
    category: str
    price: float


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=50)
    password: str = Field(min_length=1, max_length=100)

    model_config = ConfigDict(str_strip_whitespace=True)


class UserProfile(BaseModel):
    user_id: str
    username: str
    email: EmailStr
    full_name: str


class CommonHeaders(BaseModel):
    user_agent: str = Field(alias="User-Agent", min_length=1)
    accept_language: str = Field(alias="Accept-Language", min_length=1)

    model_config = ConfigDict(populate_by_name=True, str_strip_whitespace=True)

    @field_validator("accept_language")
    @classmethod
    def validate_accept_language(cls, value: str) -> str:
        if not ACCEPT_LANGUAGE_PATTERN.fullmatch(value):
            raise ValueError(
                "Accept-Language must match a valid format like en-US,en;q=0.9,es;q=0.8"
            )
        return value

    def as_response_payload(self) -> dict[str, str]:
        return {
            "User-Agent": self.user_agent,
            "Accept-Language": self.accept_language,
        }

    @classmethod
    def from_headers(cls, user_agent: str | None, accept_language: str | None) -> "CommonHeaders":
        if not user_agent:
            raise ValueError("Header 'User-Agent' is required")
        if not accept_language:
            raise ValueError("Header 'Accept-Language' is required")
        try:
            return cls.model_validate(
                {
                    "User-Agent": user_agent,
                    "Accept-Language": accept_language,
                }
            )
        except ValidationError as exc:
            message = exc.errors()[0]["msg"]
            raise ValueError(message) from exc


def validation_error_message(errors: list[dict[str, Any]]) -> str:
    if not errors:
        return "Invalid input"
    return str(errors[0].get("msg", "Invalid input"))
