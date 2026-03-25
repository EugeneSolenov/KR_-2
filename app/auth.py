from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import uuid4

from itsdangerous import BadSignature, Signer

from app.models import UserProfile

SESSION_COOKIE_NAME = "session_token"
SESSION_TTL_SECONDS = 300
SESSION_REFRESH_AFTER_SECONDS = 180
SECRET_KEY = os.getenv("APP_SECRET_KEY", "dev-secret-key-change-me")


@dataclass(slots=True)
class SessionData:
    user_id: str
    last_activity: int


class UnauthorizedError(Exception):
    """Raised when a cookie is missing."""


class InvalidCredentialsError(Exception):
    """Raised when the provided credentials are invalid."""


class InvalidSessionError(Exception):
    """Raised when a cookie signature is invalid or malformed."""


class SessionExpiredError(Exception):
    """Raised when the cookie is valid but expired."""


signer = Signer(SECRET_KEY)

_USER_RECORDS: dict[str, dict[str, str]] = {
    "user123": {
        "password": "password123",
        "user_id": str(uuid4()),
        "email": "user123@example.com",
        "full_name": "Test User 123",
    },
    "alice": {
        "password": "alicepass",
        "user_id": str(uuid4()),
        "email": "alice@example.com",
        "full_name": "Alice Johnson",
    },
}

USER_PROFILES: dict[str, UserProfile] = {
    record["user_id"]: UserProfile(
        user_id=record["user_id"],
        username=username,
        email=record["email"],
        full_name=record["full_name"],
    )
    for username, record in _USER_RECORDS.items()
}


def current_timestamp() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def authenticate_user(username: str, password: str) -> UserProfile:
    record = _USER_RECORDS.get(username)
    if not record or record["password"] != password:
        raise InvalidCredentialsError
    return USER_PROFILES[record["user_id"]]


def create_session_token(user_id: str, last_activity: int | None = None) -> str:
    timestamp = current_timestamp() if last_activity is None else last_activity
    payload = f"{user_id}.{timestamp}"
    return signer.sign(payload.encode("utf-8")).decode("utf-8")


def parse_session_token(token: str) -> SessionData:
    try:
        payload = signer.unsign(token).decode("utf-8")
    except BadSignature as exc:
        raise InvalidSessionError from exc

    try:
        user_id, timestamp_text = payload.rsplit(".", maxsplit=1)
        timestamp = int(timestamp_text)
    except ValueError as exc:
        raise InvalidSessionError from exc

    if user_id not in USER_PROFILES:
        raise InvalidSessionError

    age = current_timestamp() - timestamp
    if age > SESSION_TTL_SECONDS:
        raise SessionExpiredError
    if age < 0:
        raise InvalidSessionError

    return SessionData(user_id=user_id, last_activity=timestamp)


def should_refresh_session(last_activity: int) -> bool:
    age = current_timestamp() - last_activity
    return SESSION_REFRESH_AFTER_SECONDS <= age <= SESSION_TTL_SECONDS
