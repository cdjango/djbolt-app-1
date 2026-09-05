from django_bolt import BoltAPI, OpenAPIConfig

from allapps.core.api import router as core_app_router

api = BoltAPI(
    trailing_slash="append",
    openapi_config=OpenAPIConfig(
        title="Django Bolt App",
        description="Demo App using django-bolt framework",
        version="1.0.0",
    ),
    django_middleware={
        "exclude": ["django.middleware.csrf.CsrfViewMiddleware"],
    },
)

api.include_router(core_app_router)
