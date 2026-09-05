from typing import ClassVar

from asgiref.sync import sync_to_async
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models


class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("The Email must be set")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self.create_user(email, password, **extra_fields)

    async def acreate_user(self, email, password=None, **extra_fields):
        return await sync_to_async(self.create_user)(email, password, **extra_fields)

    async def acreate_superuser(self, email, password=None, **extra_fields):
        return await sync_to_async(self.create_superuser)(
            email, password, **extra_fields
        )


class User(AbstractUser):
    email = models.EmailField(unique=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS: ClassVar[list[str]] = []

    objects = UserManager()

    def save(self, *args, **kwargs):
        if not self.username:
            self.username = self.email
        super().save(*args, **kwargs)


class RevokedToken(models.Model):
    jti = models.CharField(max_length=255, unique=True, db_index=True)
    expires_at = models.DateTimeField(db_index=True)

    class Meta:
        indexes: ClassVar[list[models.Index]] = [
            models.Index(fields=["jti"]),
            models.Index(fields=["expires_at"]),
        ]


class UserTokenVersion(models.Model):
    user_id = models.CharField(max_length=255, primary_key=True)
    version = models.PositiveIntegerField(default=0)
