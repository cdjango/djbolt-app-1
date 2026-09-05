from django.contrib.auth import get_user_model
from django_bolt import Router
from django_bolt.auth import DjangoORMRevocation, IsAuthenticated, JWTAuthentication
from django_bolt.auth.tokens import (
    TokenRotationError,
    create_token_pair,
    rotate_refresh_token,
    set_token_cookies,
)
from django_bolt.exceptions import HTTPException, Unauthorized
from django_bolt.responses import JSON

from .schemas import LoginOut, RegisterIn, UserOut

User = get_user_model()
router = Router(prefix="/api")
store = DjangoORMRevocation(model="auth_app.RevokedToken")


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

    return set_token_cookies(
        JSON({"access_token": pair.access_token}),
        pair,
        refresh_cookie="refresh_token",
        refresh_path="/api/auth",
        secure=True,
    )


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

    return set_token_cookies(
        JSON({"ok": True}),
        pair,
        refresh_cookie="refresh_token",
        refresh_path="/api/auth",
        secure=True,
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
    await store.revoke_family(claims["fam"], exp=claims.get("exp"))
    response = JSON({"ok": True})
    response.delete_cookie("access_token", path="/")
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
    try:
        await store.bump_user_version(user_id)
    except NotImplementedError:
        claims = request["context"]["auth_claims"]
        await store.revoke_family(claims["fam"], exp=claims.get("exp"))
    response = JSON({"ok": True})
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/api/auth")
    return response


jwt_auth = JWTAuthentication(revocation_store=store)


@router.get("/auth/me", auth=[jwt_auth], guards=[IsAuthenticated()], tags=["auth"])
async def me(request) -> UserOut:
    """
    Current user (me)
    """
    user = request.user
    return UserOut(
        id=user.id,
        email=user.email,
        first_name=user.first_name,
        last_name=user.last_name,
        is_staff=user.is_staff,
        is_active=user.is_active,
    )
