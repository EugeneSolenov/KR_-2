from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from app import auth
from app.models import CommonHeaders, LoginRequest, Product, UserCreate, UserProfile, validation_error_message

app = FastAPI(
    title="Control Work #2",
    description="FastAPI application covering user creation, products, cookies, and headers tasks.",
    version="1.0.0",
)

PRODUCTS = [
    Product(product_id=123, name="Smartphone", category="Electronics", price=599.99),
    Product(product_id=456, name="Phone Case", category="Accessories", price=19.99),
    Product(product_id=789, name="Iphone", category="Electronics", price=1299.99),
    Product(product_id=101, name="Headphones", category="Accessories", price=99.99),
    Product(product_id=202, name="Smartwatch", category="Electronics", price=299.99),
]
PRODUCTS_BY_ID = {product.product_id: product for product in PRODUCTS}


@app.exception_handler(auth.UnauthorizedError)
async def unauthorized_handler(_: Request, __: auth.UnauthorizedError) -> JSONResponse:
    return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Unauthorized"})


@app.exception_handler(auth.InvalidCredentialsError)
async def invalid_credentials_handler(_: Request, __: auth.InvalidCredentialsError) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={"message": "Invalid credentials"},
    )


@app.exception_handler(auth.InvalidSessionError)
async def invalid_session_handler(_: Request, __: auth.InvalidSessionError) -> JSONResponse:
    return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Invalid session"})


@app.exception_handler(auth.SessionExpiredError)
async def session_expired_handler(_: Request, __: auth.SessionExpiredError) -> JSONResponse:
    return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"message": "Session expired"})


async def parse_login_request(request: Request) -> LoginRequest:
    content_type = request.headers.get("content-type", "")
    payload: dict[str, Any]

    try:
        if "application/json" in content_type:
            payload = await request.json()
        else:
            form_data = await request.form()
            payload = dict(form_data)
    except Exception as exc:  # pragma: no cover - defensive guard for malformed payloads
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid request body") from exc

    try:
        return LoginRequest.model_validate(payload)
    except ValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=validation_error_message(exc.errors()),
        ) from exc


def set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=auth.SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=False,
        max_age=auth.SESSION_TTL_SECONDS,
        samesite="lax",
    )


def get_current_user(request: Request, response: Response) -> UserProfile:
    token = request.cookies.get(auth.SESSION_COOKIE_NAME)
    if not token:
        raise auth.UnauthorizedError

    session = auth.parse_session_token(token)
    profile = auth.USER_PROFILES[session.user_id]

    if auth.should_refresh_session(session.last_activity):
        refreshed_token = auth.create_session_token(profile.user_id)
        set_session_cookie(response, refreshed_token)

    return profile


def get_common_headers(
    user_agent: Annotated[str | None, Header(alias="User-Agent")] = None,
    accept_language: Annotated[str | None, Header(alias="Accept-Language")] = None,
) -> CommonHeaders:
    try:
        return CommonHeaders.from_headers(user_agent=user_agent, accept_language=accept_language)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


AuthenticatedUser = Annotated[UserProfile, Depends(get_current_user)]
HeaderPayload = Annotated[CommonHeaders, Depends(get_common_headers)]


@app.get("/")
def read_root() -> dict[str, str]:
    return {"message": "FastAPI control work app is running"}


@app.post("/create_user", response_model=UserCreate)
def create_user(user: UserCreate) -> UserCreate:
    return user


@app.get("/products/search", response_model=list[Product])
def search_products(
    keyword: str = Query(..., min_length=1),
    category: str | None = Query(default=None, min_length=1),
    limit: int = Query(default=10, ge=1),
) -> list[Product]:
    keyword_lower = keyword.lower()
    filtered = [
        product
        for product in PRODUCTS
        if keyword_lower in product.name.lower()
        and (category is None or product.category.lower() == category.lower())
    ]
    return filtered[:limit]


@app.get("/product/{product_id}", response_model=Product)
def get_product(product_id: int) -> Product:
    product = PRODUCTS_BY_ID.get(product_id)
    if product is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Product not found")
    return product


@app.post("/login")
async def login(request: Request, response: Response) -> dict[str, Any]:
    credentials = await parse_login_request(request)
    profile = auth.authenticate_user(credentials.username, credentials.password)
    token = auth.create_session_token(profile.user_id)
    set_session_cookie(response, token)
    return {
        "message": "Login successful",
        "user": profile.model_dump(),
    }


@app.get("/user")
def read_user_profile(current_user: AuthenticatedUser) -> dict[str, Any]:
    return current_user.model_dump()


@app.get("/profile")
def read_profile(current_user: AuthenticatedUser) -> dict[str, Any]:
    return {
        "message": "Profile loaded successfully",
        "user": current_user.model_dump(),
    }


@app.get("/headers")
def read_headers(headers: HeaderPayload) -> dict[str, str]:
    return headers.as_response_payload()


@app.get("/info")
def read_info(response: Response, headers: HeaderPayload) -> dict[str, Any]:
    response.headers["X-Server-Time"] = datetime.now().isoformat(timespec="seconds")
    return {
        "message": "Добро пожаловать! Ваши заголовки успешно обработаны.",
        "headers": headers.as_response_payload(),
    }
