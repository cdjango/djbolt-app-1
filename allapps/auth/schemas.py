import msgspec


class RegisterIn(msgspec.Struct):
    email: str
    password: str


class UserOut(msgspec.Struct):
    id: int
    email: str
    first_name: str
    last_name: str
    is_staff: bool
    is_active: bool
