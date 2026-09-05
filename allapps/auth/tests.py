import jwt
from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import TestCase, TransactionTestCase
from django_bolt.testing import TestClient

from djboltdemo.api import api

User = get_user_model()

BASE_URL = "https://testserver"
SAME_ORIGIN_HEADERS = {
    "Origin": BASE_URL,
    "Sec-Fetch-Site": "same-origin",
}


def _client():
    return TestClient(api, base_url=BASE_URL)


def _cookie(client, name):
    for c in client.cookies.jar:
        if c.name == name:
            return c
    return None


class RegisterApiTests(TestCase):
    def test_register_creates_user(self):
        with _client() as c:
            r = c.post(
                "/api/auth/register/",
                json={"email": "a@example.com", "password": "secret123"},
            )
            self.assertEqual(r.status_code, 200)
            self.assertEqual(
                r.json(),
                {
                    "id": r.json()["id"],
                    "email": "a@example.com",
                    "first_name": "",
                    "last_name": "",
                    "is_staff": False,
                    "is_active": True,
                },
            )
            self.assertTrue(User.objects.filter(email="a@example.com").exists())

    def test_register_rejects_duplicate_email(self):
        User.objects.create_user(email="dup@example.com", password="secret123")
        with _client() as c:
            r = c.post(
                "/api/auth/register/",
                json={"email": "dup@example.com", "password": "secret123"},
            )
            self.assertEqual(r.status_code, 401)
            self.assertEqual(r.json(), {"detail": "Email exists"})


class LoginApiTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="login@example.com", password="secret123"
        )

    def login(self, c, email="login@example.com", password="secret123"):
        return c.post("/api/auth/login/", json={"email": email, "password": password})

    def test_login_returns_access_token_in_body_and_refresh_in_cookie(self):
        with _client() as c:
            r = self.login(c)
            self.assertEqual(r.status_code, 200)
            body = r.json()
            self.assertIn("access_token", body)

            claims = jwt.decode(
                body["access_token"], settings.SECRET_KEY, algorithms=["HS256"]
            )
            self.assertEqual(claims["typ"], "access")
            self.assertEqual(claims["sub"], str(self.user.id))
            self.assertEqual(claims["amr"], ["pwd"])

            refresh = _cookie(c, "refresh_token")
            self.assertIsNotNone(refresh)
            self.assertTrue(refresh.has_nonstandard_attr("HttpOnly"))
            self.assertTrue(refresh.secure)
            self.assertEqual(refresh.path, "/api/auth")
            refresh_claims = jwt.decode(
                refresh.value, settings.SECRET_KEY, algorithms=["HS256"]
            )
            self.assertEqual(refresh_claims["typ"], "refresh")

            access = _cookie(c, "access_token")
            self.assertIsNone(access)

    def test_login_invalid_password(self):
        with _client() as c:
            r = self.login(c, password="wrong-password")
            self.assertEqual(r.status_code, 401)
            self.assertEqual(r.json(), {"detail": "Invalid credentials"})

    def test_login_unknown_email(self):
        with _client() as c:
            r = self.login(c, email="nobody@example.com")
            self.assertEqual(r.status_code, 401)
            self.assertEqual(r.json(), {"detail": "Invalid credentials"})

    def test_login_inactive_user(self):
        self.user.is_active = False
        self.user.save()
        with _client() as c:
            r = self.login(c)
            self.assertEqual(r.status_code, 401)
            self.assertEqual(r.json(), {"detail": "Invalid credentials"})


class MeApiTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="me@example.com", password="secret123"
        )

    def login(self, c):
        return c.post(
            "/api/auth/login/",
            json={"email": "me@example.com", "password": "secret123"},
        )

    def test_me_returns_current_user_with_valid_token(self):
        with _client() as c:
            login = self.login(c)
            access = login.json()["access_token"]
            r = c.get("/api/auth/me/", headers={"Authorization": f"Bearer {access}"})
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.json()["id"], self.user.id)
            self.assertEqual(r.json()["email"], "me@example.com")

    def test_me_requires_token(self):
        with _client() as c:
            r = c.get("/api/auth/me/")
            self.assertEqual(r.status_code, 401)
            self.assertEqual(r.json(), {"detail": "Authentication required"})

    def test_me_rejects_invalid_token(self):
        with _client() as c:
            r = c.get("/api/auth/me/", headers={"Authorization": "Bearer not-a-jwt"})
            self.assertEqual(r.status_code, 401)


class RefreshApiTests(TransactionTestCase):
    def setUp(self):
        User.objects.create_user(email="refresh@example.com", password="secret123")

    def login(self, c):
        return c.post(
            "/api/auth/login/",
            json={"email": "refresh@example.com", "password": "secret123"},
        )

    def test_refresh_rotates_tokens(self):
        with _client() as c:
            self.login(c)
            before = _cookie(c, "refresh_token").value
            r = c.post("/api/auth/refresh/", headers=SAME_ORIGIN_HEADERS)
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.json(), {"ok": True})
            after = _cookie(c, "refresh_token").value
            self.assertNotEqual(before, after)
            self.assertIsNone(_cookie(c, "access_token"))

    def test_refresh_requires_cookie(self):
        with _client() as c:
            r = c.post("/api/auth/refresh/", headers=SAME_ORIGIN_HEADERS)
            self.assertEqual(r.status_code, 401)

    def test_refresh_requires_same_origin(self):
        with _client() as c:
            self.login(c)
            r = c.post("/api/auth/refresh/")
            self.assertEqual(r.status_code, 403)

    def test_replayed_refresh_token_burns_family(self):
        with _client() as c:
            self.login(c)
            before = _cookie(c, "refresh_token").value
            r = c.post("/api/auth/refresh/", headers=SAME_ORIGIN_HEADERS)
            self.assertEqual(r.status_code, 200)
            after = _cookie(c, "refresh_token").value
            self.assertNotEqual(before, after)

        with _client() as c:
            r = c.post(
                "/api/auth/refresh/",
                headers={**SAME_ORIGIN_HEADERS, "Cookie": f"refresh_token={before}"},
            )
            self.assertEqual(r.status_code, 401)
            self.assertEqual(r.json(), {"detail": "Invalid token"})

        with _client() as c:
            r = c.post(
                "/api/auth/refresh/",
                headers={**SAME_ORIGIN_HEADERS, "Cookie": f"refresh_token={after}"},
            )
            self.assertEqual(r.status_code, 401)
            self.assertEqual(r.json(), {"detail": "Invalid token"})


class LogoutApiTests(TestCase):
    def setUp(self):
        User.objects.create_user(email="logout@example.com", password="secret123")

    def authenticated_refresh_cookie(self, c):
        c.post(
            "/api/auth/login/",
            json={"email": "logout@example.com", "password": "secret123"},
        )
        return _cookie(c, "refresh_token").value

    def test_logout_ok(self):
        with _client() as c:
            self.authenticated_refresh_cookie(c)
            r = c.post("/api/auth/logout/", headers=SAME_ORIGIN_HEADERS)
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.json(), {"ok": True})
            self.assertIsNone(_cookie(c, "refresh_token"))

    def test_refresh_rejected_after_logout(self):
        with _client() as c:
            refresh = self.authenticated_refresh_cookie(c)
            r = c.post("/api/auth/logout/", headers=SAME_ORIGIN_HEADERS)
            self.assertEqual(r.status_code, 200)

        with _client() as c:
            r = c.post(
                "/api/auth/refresh/",
                headers={**SAME_ORIGIN_HEADERS, "Cookie": f"refresh_token={refresh}"},
            )
            self.assertEqual(r.status_code, 401)
            self.assertEqual(r.json(), {"detail": "Invalid token"})


class LogoutAllApiTests(TestCase):
    def setUp(self):
        User.objects.create_user(email="logoutall@example.com", password="secret123")

    def authenticated_refresh_cookie(self, c):
        c.post(
            "/api/auth/login/",
            json={"email": "logoutall@example.com", "password": "secret123"},
        )
        return _cookie(c, "refresh_token").value

    def test_logout_all_ok(self):
        with _client() as c:
            self.authenticated_refresh_cookie(c)
            r = c.post("/api/auth/logout-all/", headers=SAME_ORIGIN_HEADERS)
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.json(), {"ok": True})
            self.assertIsNone(_cookie(c, "refresh_token"))

    def test_refresh_rejected_after_logout_all(self):
        with _client() as c:
            refresh = self.authenticated_refresh_cookie(c)
            r = c.post("/api/auth/logout-all/", headers=SAME_ORIGIN_HEADERS)
            self.assertEqual(r.status_code, 200)

        with _client() as c:
            r = c.post(
                "/api/auth/refresh/",
                headers={**SAME_ORIGIN_HEADERS, "Cookie": f"refresh_token={refresh}"},
            )
            self.assertEqual(r.status_code, 401)
            self.assertEqual(r.json(), {"detail": "Invalid token"})
