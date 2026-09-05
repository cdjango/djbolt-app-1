from django.apps import apps
from django.db.models import F
from django_bolt.auth import DjangoORMRevocation

VERSION_MODEL = "auth_app.UserTokenVersion"


class VersionedRevocation(DjangoORMRevocation):
    """``DjangoORMRevocation`` with working per-user token versioning.

    Access tokens and refresh tokens both embed a ``ver`` claim minted from
    ``store.get_user_version(user_id)``. Bumping the version on logout-all
    immediately invalidates every previously issued token for that user,
    including already-distributed access tokens.
    """

    def __init__(self, model: str):
        super().__init__(model=model)
        self._version_model = None

    @property
    def version_model(self):
        if self._version_model is None:
            self._version_model = apps.get_model(*VERSION_MODEL.split("."))
        return self._version_model

    async def get_user_version(self, user_id: str) -> int:
        row = await self.version_model.objects.filter(user_id=user_id).afirst()
        return row.version if row else 0

    async def bump_user_version(self, user_id: str) -> int:
        updated = await self.version_model.objects.filter(user_id=user_id).aupdate(
            version=F("version") + 1
        )
        if not updated:
            await self.version_model.objects.acreate(user_id=user_id, version=1)
        obj = await self.version_model.objects.aget(user_id=user_id)
        return obj.version
