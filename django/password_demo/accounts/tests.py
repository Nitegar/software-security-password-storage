from django.contrib.auth.models import User
from django.test import TestCase

STRONG_PASSWORD = "correct-horse-battery-staple"


class AuthFlowTests(TestCase):
    def register(self, username="alice", password=STRONG_PASSWORD):
        return self.client.post(
            "/auth/register/", {"username": username, "password": password}
        )

    def test_register_stores_argon2_hash(self):
        response = self.register()
        self.assertEqual(response.status_code, 200)

        user = User.objects.get(username="alice")
        self.assertTrue(user.password.startswith("argon2$"))
        self.assertNotIn(STRONG_PASSWORD, user.password)

    def test_short_password_rejected(self):
        response = self.register(password="tooshort")
        self.assertEqual(response.status_code, 400)
        self.assertFalse(User.objects.filter(username="alice").exists())

    def test_duplicate_username_rejected(self):
        self.register()
        response = self.register()
        self.assertEqual(response.status_code, 400)

    def test_login_and_logout(self):
        self.register()

        response = self.client.post(
            "/auth/login/", {"username": "alice", "password": STRONG_PASSWORD}
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("_auth_user_id", self.client.session)

        response = self.client.post("/auth/logout/")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_login_wrong_password(self):
        self.register()
        response = self.client.post(
            "/auth/login/", {"username": "alice", "password": "wrong-password-123"}
        )
        self.assertEqual(response.status_code, 401)
