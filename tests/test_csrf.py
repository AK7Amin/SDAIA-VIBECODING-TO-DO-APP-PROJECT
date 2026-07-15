"""RED-phase tests for security fix #2: CSRF protection.

Vulnerability (High): sessions ride on a cookie, and every state-changing
route accepts form-encoded requests. A malicious page on another site can
auto-submit such a request from the victim's browser and the cookie goes
along for the ride — creating tasks, logging the victim out, etc.

Contract imposed on app.py:
  - POST/PATCH/DELETE without a valid CSRF token  -> 403
  - the token travels in the X-CSRF-Token header (or csrf_token form field)
  - the session cookie is issued with SameSite=Lax and HttpOnly
  - config flag CSRF_ENABLED (default ON; the rest of the test suite runs
    with it off so older tests stay focused on their own concerns)
"""
import os
import tempfile

import pytest

from app import create_app

EMAIL = "user@example.com"
PASSWORD = "S3cure!passphrase"


@pytest.fixture
def app():
    """Overrides the conftest fixture: CSRF explicitly ENABLED here."""
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    app = create_app(
        {
            "TESTING": True,
            "DATABASE": db_path,
            "SECRET_KEY": "test-only-secret",
            "CSRF_ENABLED": True,
        }
    )
    yield app
    os.close(db_fd)
    os.unlink(db_path)


def plant_token(client, token="planted-csrf-token"):
    """Put a known CSRF token straight into the session cookie."""
    with client.session_transaction() as sess:
        sess["csrf_token"] = token
    return token


def read_token(client):
    with client.session_transaction() as sess:
        return sess.get("csrf_token")


def register(client, token=None):
    headers = {"X-CSRF-Token": token} if token else {}
    return client.post(
        "/register",
        data={"email": EMAIL, "password": PASSWORD},
        headers=headers,
    )


def login(client, token=None):
    headers = {"X-CSRF-Token": token} if token else {}
    return client.post(
        "/login",
        data={"email": EMAIL, "password": PASSWORD},
        headers=headers,
    )


class TestCsrfRejection:
    def test_post_without_token_is_rejected(self, client):
        assert register(client).status_code == 403

    def test_post_with_wrong_token_is_rejected(self, client):
        plant_token(client, "the-real-token")
        resp = client.post(
            "/register",
            data={"email": EMAIL, "password": PASSWORD},
            headers={"X-CSRF-Token": "attacker-guess"},
        )
        assert resp.status_code == 403

    def test_tasks_routes_require_token_even_when_logged_in(self, client):
        token = plant_token(client)
        assert register(client, token).status_code == 201
        assert login(client, token).status_code == 200

        # Logged in — but a cross-site style request (no token) must die.
        resp = client.post("/tasks", data={"title": "forged task"})
        assert resp.status_code == 403, "CSRF: cookie alone must not be enough"


class TestCsrfAcceptance:
    def test_valid_token_lets_the_full_flow_work(self, client):
        token = plant_token(client)
        assert register(client, token).status_code == 201
        assert login(client, token).status_code == 200

        # Login rotates the session — fetch the fresh token like the page would.
        token = read_token(client)
        assert token, "login must leave a CSRF token in the session"

        resp = client.post(
            "/tasks", data={"title": "legit task"}, headers={"X-CSRF-Token": token}
        )
        assert resp.status_code == 201


class TestSessionCookieFlags:
    def test_session_cookie_is_samesite_lax_and_httponly(self, client):
        token = plant_token(client)
        register(client, token)
        resp = login(client, token)

        cookie = resp.headers.get("Set-Cookie", "")
        assert "session=" in cookie
        assert "SameSite=Lax" in cookie, "session cookie missing SameSite=Lax"
        assert "HttpOnly" in cookie, "session cookie readable by page JS"


class TestTokenReachesThePage:
    def test_dashboard_embeds_the_csrf_token_for_fetch_calls(self, client):
        token = plant_token(client)
        register(client, token)
        login(client, token)

        token = read_token(client)
        page = client.get("/dashboard").get_data(as_text=True)
        assert 'name="csrf-token"' in page, "dashboard missing csrf meta tag"
        assert token in page, "dashboard must embed the session's CSRF token"
