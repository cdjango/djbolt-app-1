from django.urls import path

from . import api

app_name = "core"

urlpatterns = [
    path("", api.greeting, name="greeting"),
]
