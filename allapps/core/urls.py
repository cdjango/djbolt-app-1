from django.urls import path

from . import api

app_name = "core"

urlpatterns = [
    path("", api.greeting, name="greeting"),
    path("auth/register", api.register, name="register"),
    path("auth/login", api.login_user, name="login"),
    path("auth/logout", api.logout, name="logout"),
    path("auth/me", api.me, name="me"),
    path("auth/refresh", api.refresh_token, name="refresh"),
]
