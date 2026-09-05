from django.contrib.auth import get_user_model
from django_bolt import Router
from django_bolt.auth import (
    InMemoryRevocation,
    IsAuthenticated,
    JWTAuthentication,
    JWTAuthViews,
    LoginCredentials,
)
from django_bolt.exceptions import Unauthorized

from .schemas import RegisterIn, UserOut

User = get_user_model()
router = Router(prefix="/api")
store = InMemoryRevocation()


async def credential_validator(creds: LoginCredentials) -> get_user_model() | None:
    try:
        user = await User.objects.aget(email=creds.email)
    except User.DoesNotExist:
        return None

    if not await user.acheck_password(creds.password):
        return None

    if not user.is_active:
        return None
    return user


# This auto-adds: POST /api/auth/login, /api/auth/refresh, /api/auth/logout, /api/auth/logout-all
auth_views = JWTAuthViews(
    store=store,
    credential_validator=credential_validator,
)

auth_views.register(router)


@router.post("/auth/register", tags=["auth"])
async def register(data: RegisterIn) -> UserOut:
    """
    Register / SignUP
    """
    if await User.objects.filter(email=data.email).aexists():
        raise Unauthorized("Email exists")
    user = await User.objects.acreate_user(email=data.email, password=data.password)
    return UserOut(
        id=user.id,
        email=user.email,
        first_name=user.first_name,
        last_name=user.last_name,
        is_staff=user.is_staff,
        is_active=user.is_active,
    )


# This is the "me" endpoint - requires valid access token
# auth=[...] attempts validation, guards=[IsAuthenticated()] enforces 401
jwt_auth = JWTAuthentication(revocation_store=store)


@router.get("/auth/me", auth=[jwt_auth], guards=[IsAuthenticated()], tags=["auth"])
async def me(request) -> UserOut:
    """
    Current user (me)
    """
    # request.user is lazy-loaded, request.context has raw claims
    user = request.user
    # request.context = {"user_id": 1, "exp": ..., "type": "access"}
    return UserOut(
        id=user.id,
        email=user.email,
        first_name=user.first_name,
        last_name=user.last_name,
        is_staff=user.is_staff,
        is_active=user.is_active,
    )
