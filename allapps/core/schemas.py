import msgspec


class RegisterRequest(msgspec.Struct):
    email: str
    password: str


class LoginRequest(msgspec.Struct):
    email: str
    password: str


class UserResponse(msgspec.Struct):
    id: int
    email: str
    first_name: str
    last_name: str
    is_staff: bool
    is_active: bool


class TokenRefreshResponse(msgspec.Struct):
    token: str
