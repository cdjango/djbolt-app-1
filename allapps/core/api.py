from django.contrib.auth import aauthenticate, alogin, get_user_model
from django.views.decorators.csrf import csrf_exempt
from django_bolt import BoltAPI, Request
from django_bolt.auth import (
    IsAuthenticated,
    JWTAuthentication,
    create_jwt_for_user,
    get_current_user,
)
from django_bolt.params import Depends

from .schemas import LoginRequest, RegisterRequest, UserResponse

User = get_user_model()
api = BoltAPI(django_middleware=True)


@api.get("/")
def greeting():
    return {"message": "Hello World"}


jwt_auth = [JWTAuthentication()]


@api.post("/auth/register")
async def register(data: RegisterRequest):
    if await User.objects.filter(email=data.email).aexists():
        return {"error": "Email already registered"}, 409
    user = User(email=data.email)
    user.set_password(data.password)
    user.username = data.email
    await user.asave()
    token = create_jwt_for_user(user)
    return {
        "token": token,
        "user": UserResponse(
            id=user.id,
            email=user.email,
            first_name=user.first_name,
            last_name=user.last_name,
            is_staff=user.is_staff,
            is_active=user.is_active,
        ),
    }


@api.post("/auth/login")
@csrf_exempt
async def login_user(request: Request, data: LoginRequest):
    user = await aauthenticate(request, email=data.email, password=data.password)
    if user is None:
        return {"error": "Invalid credentials"}, 401

    await alogin(request, user)
    token = create_jwt_for_user(user)
    return {
        "token": token,
        "user": UserResponse(
            id=user.id,
            email=user.email,
            first_name=user.first_name,
            last_name=user.last_name,
            is_staff=user.is_staff,
            is_active=user.is_active,
        ),
    }


@api.post("/auth/logout", auth=jwt_auth, guards=[IsAuthenticated()])
def logout():
    return {"message": "Logged out successfully"}


@api.get("/auth/me", auth=jwt_auth, guards=[IsAuthenticated()])
async def me(user=Depends(get_current_user)):
    return UserResponse(
        id=user.id,
        email=user.email,
        first_name=user.first_name,
        last_name=user.last_name,
        is_staff=user.is_staff,
        is_active=user.is_active,
    )
