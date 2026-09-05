from __future__ import annotations

import time

import jwt
from django.conf import settings
from django.contrib.auth import get_user_model
from django_bolt import Router
from django_bolt.auth import IsAuthenticated, JWTAuthentication
from django_bolt.auth.tokens import (
    TokenPair,
    TokenRotationError,
    create_token_pair,
    rotate_refresh_token,
)
from django_bolt.exceptions import HTTPException, Unauthorized
from django_bolt.responses import JSON

from .revocation import VersionedRevocation
from .schemas import LoginOut, RegisterIn, UserOut

User = get_user_model()
router = Router(prefix="/api")
store = VersionedRevocation(model="auth_app.RevokedToken")


async def credential_validator(creds: RegisterIn) -> get_user_model() | None:
    try:
        user = await User.objects.aget(email=creds.email)
    except User.DoesNotExist:
        return None

    if not await user.acheck_password(creds.password):
        return None

    if not user.is_active:
        return None
    return user


async def _user_version(user_id: str) -> int:
    try:
        return await store.get_user_version(user_id)
    except NotImplementedError:
        return 0


def _set_refresh_cookie(response, pair: TokenPair):
    now = time.time()
    max_age = max(0, int(pair.refresh_claims["exp"]) - int(now))
    response.set_cookie(
        "refresh_token",
        pair.refresh_token,
        max_age=max_age,
        path="/api/auth",
        secure=True,
        httponly=True,
        samesite="Lax",
    )
    return response


@router.post("/auth/login", tags=["auth"], summary="Log in with email and password")
async def login_view(request, data: RegisterIn) -> LoginOut:
    user = await credential_validator(data)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    version = await _user_version(str(user.pk))
    pair = create_token_pair(
        user,
        version=version,
        method="pwd",
    )

    return _set_refresh_cookie(
        JSON({"access_token": pair.access_token}),
        pair,
    )


async def revoke_presented_access_token(request):
    headers = request["headers"] or {}
    auth = headers.get("authorization") or headers.get("Authorization", "")
    if not auth.lower().startswith("bearer "):
        return
    token = auth.split(" ", 1)[1].strip()
    if not token:
        return
    try:
        claims = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
    except jwt.InvalidTokenError:
        return
    if claims.get("typ") != "access":
        return
    jti = claims.get("jti")
    if jti:
        await store.revoke(jti, exp=claims.get("exp"))


@router.post("/auth/register", tags=["auth"])
async def register(data: RegisterIn) -> UserOut:
    """
    Register / SignUP
    """
    if await User.objects.filter(email=data.email).aexists():
        raise Unauthorized(detail="Email exists")
    user = await User.objects.acreate_user(email=data.email, password=data.password)
    return UserOut(
        id=user.id,
        email=user.email,
        first_name=user.first_name,
        last_name=user.last_name,
        is_staff=user.is_staff,
        is_active=user.is_active,
    )


refresh_auth = JWTAuthentication(
    cookie="refresh_token",
    token_type="refresh",
    require_jti=True,
)


@router.post(
    "/auth/refresh",
    auth=[refresh_auth],
    guards=[IsAuthenticated()],
    tags=["auth"],
    summary="Refresh tokens",
)
async def refresh_view(request):
    try:
        pair = await rotate_refresh_token(
            request["context"]["auth_claims"],
            store=store,
        )
    except TokenRotationError:
        raise HTTPException(status_code=401, detail="Invalid token")

    return _set_refresh_cookie(
        JSON({"ok": True}),
        pair,
    )


@router.post(
    "/auth/logout",
    auth=[refresh_auth],
    guards=[IsAuthenticated()],
    tags=["auth"],
    summary="Log out",
)
async def logout_view(request):
    claims = request["context"]["auth_claims"]
    await revoke_presented_access_token(request)
    await store.revoke_family(claims["fam"], exp=claims.get("exp"))
    response = JSON({"ok": True})
    response.delete_cookie("refresh_token", path="/api/auth")
    return response


@router.post(
    "/auth/logout-all",
    auth=[refresh_auth],
    guards=[IsAuthenticated()],
    tags=["auth"],
    summary="Log out everywhere",
)
async def logout_all_view(request):
    user_id = request["context"]["user_id"]
    await store.bump_user_version(user_id)
    response = JSON({"ok": True})
    response.delete_cookie("refresh_token", path="/api/auth")
    return response


jwt_auth = JWTAuthentication(revocation_store=store)


@router.get("/auth/me", auth=[jwt_auth], guards=[IsAuthenticated()], tags=["auth"])
async def me(request) -> UserOut:
    """
    Current user (me)
    """
    claims = request["context"]["auth_claims"]
    user_id = claims.get("sub")
    token_version = int(claims.get("ver", 0))
    current_version = await store.get_user_version(str(user_id))
    if token_version != current_version:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = request.user
    return UserOut(
        id=user.id,
        email=user.email,
        first_name=user.first_name,
        last_name=user.last_name,
        is_staff=user.is_staff,
        is_active=user.is_active,
    )
