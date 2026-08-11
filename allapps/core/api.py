import time
import uuid

import jwt
from django.conf import settings
from django.contrib.auth import aauthenticate, get_user_model
from django_bolt import BoltAPI, Request
from django_bolt.auth import (
    IsAuthenticated,
    JWTAuthentication,
    TokenRotationError,
    create_token_pair,
    get_current_user,
    rotate_refresh_token,
)
from django_bolt.auth.revocation import InMemoryRevocation
from django_bolt.params import Depends
from django_bolt.responses import JSON

from .schemas import LoginRequest, RegisterRequest, UserResponse

User = get_user_model()
api = BoltAPI(
    django_middleware={
        "exclude": ["django.middleware.csrf.CsrfViewMiddleware"],
    }
)

ACCESS_TTL = 300
REFRESH_COOKIE = "refresh_token"
REFRESH_PATH = "/auth/refresh"
SECURE_COOKIES = not settings.DEBUG

revocation_store = InMemoryRevocation()
access_auth = [JWTAuthentication(revocation_store=revocation_store)]
refresh_auth = [
    JWTAuthentication(
        cookie=REFRESH_COOKIE,
        token_type="refresh",
        revocation_store=revocation_store,
    )
]


def _user_payload(user):
    return UserResponse(
        id=user.id,
        email=user.email,
        first_name=user.first_name,
        last_name=user.last_name,
        is_staff=user.is_staff,
        is_active=user.is_active,
    )


def _mint_access_token(user_id, *, ver=0, oat=None, amr=None):
    now = int(time.time())
    claims = {
        "sub": str(user_id),
        "iat": now,
        "exp": now + ACCESS_TTL,
        "typ": "access",
        "jti": str(uuid.uuid4()),
        "ver": ver,
    }
    if oat is not None:
        claims["oat"] = oat
    if amr:
        claims["amr"] = amr
    return jwt.encode(claims, settings.SECRET_KEY, algorithm="HS256")


def _set_refresh_cookie(response, pair):
    refresh_max_age = int(pair.refresh_claims["exp"]) - int(time.time())
    return response.set_cookie(
        REFRESH_COOKIE,
        pair.refresh_token,
        max_age=refresh_max_age,
        path=REFRESH_PATH,
        secure=SECURE_COOKIES,
        httponly=True,
        samesite="strict",
    )


@api.get("/")
def greeting():
    return {"message": "Hello World"}


@api.post("/auth/register")
async def register(data: RegisterRequest):
    if await User.objects.filter(email=data.email).aexists():
        return JSON({"error": "Email already registered"}, status_code=409)
    user = User(email=data.email)
    user.set_password(data.password)
    await user.asave()
    return {"user": _user_payload(user)}


@api.post("/auth/login")
async def login_user(request: Request, data: LoginRequest):
    user = await aauthenticate(request, email=data.email, password=data.password)
    if user is None:
        return JSON({"error": "Invalid credentials"}, status_code=401)

    user_id = str(user.pk)
    version = await revocation_store.get_user_version(user_id)
    pair = create_token_pair(user, version=version)
    return _set_refresh_cookie(
        JSON(
            {
                "access_token": _mint_access_token(user_id, ver=version),
                "user": _user_payload(user),
            }
        ),
        pair,
    )


@api.post("/auth/logout", auth=access_auth, guards=[IsAuthenticated()])
async def logout(request: Request):
    claims = request["context"].get("auth_claims", {})
    jti = claims.get("jti")
    if jti:
        await revocation_store.revoke(jti, exp=claims.get("exp"))
    return JSON({"message": "Logged out successfully"}).delete_cookie(
        REFRESH_COOKIE, path=REFRESH_PATH
    )


@api.get("/auth/me", auth=access_auth, guards=[IsAuthenticated()])
async def me(user=Depends(get_current_user)):
    return _user_payload(user)


@api.post("/auth/refresh", auth=refresh_auth, guards=[IsAuthenticated()])
async def refresh_token(request: Request):
    claims = request["context"].get("auth_claims", {})
    try:
        pair = await rotate_refresh_token(claims, store=revocation_store)
    except TokenRotationError:
        return JSON({"error": "Invalid refresh token"}, status_code=401)
    access_token = _mint_access_token(
        claims["sub"],
        ver=claims.get("ver", 0),
        oat=claims.get("oat"),
        amr=claims.get("amr"),
    )
    return _set_refresh_cookie(
        JSON({"access_token": access_token}),
        pair,
    )
