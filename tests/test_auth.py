"""RED-phase tests for registration & login (PRD section 2, CLAUDE.md sections 1-2).

Behavior under test:
1. Registration stores a bcrypt hash, never the plain-text password.
2. A SQL-injection login attempt must fail and leak nothing.
3. The 6th login attempt after 5 failures is rate-limited, even with the correct password.
"""
import sqlite3

import bcrypt

EMAIL = "user@example.com"
PASSWORD = "S3cure!passphrase"


def register(client, email=EMAIL, password=PASSWORD):
    return client.post("/register", data={"email": email, "password": password})


def login(client, email=EMAIL, password=PASSWORD):
    return client.post("/login", data={"email": email, "password": password})


class TestRegistrationHashing:
    def test_register_succeeds(self, client):
        resp = register(client)
        assert resp.status_code in (201, 302)

    def test_password_stored_as_bcrypt_hash_not_plaintext(self, client, db_path):
        register(client)

        con = sqlite3.connect(db_path)
        try:
            row = con.execute(
                "SELECT password_hash FROM users WHERE email = ?", (EMAIL,)
            ).fetchone()
        finally:
            con.close()

        assert row is not None, "user row was not created"
        stored = row[0]
        if isinstance(stored, str):
            stored = stored.encode("utf-8")

        assert stored != PASSWORD.encode("utf-8"), "password stored in plain text!"
        assert stored.startswith(b"$2"), "hash is not bcrypt format ($2a/$2b prefix)"
        assert bcrypt.checkpw(PASSWORD.encode("utf-8"), stored)


class TestLoginSqlInjection:
    INJECTIONS = [
        "' OR '1'='1' --",
        "'; DROP TABLE users; --",
        "admin' --",
    ]

    def test_sql_injection_login_attempts_fail(self, client):
        register(client)

        for payload in self.INJECTIONS:
            resp = login(client, email=payload, password=payload)
            assert resp.status_code == 401, f"injection accepted: {payload!r}"
            with client.session_transaction() as sess:
                assert "user_id" not in sess, f"session created for: {payload!r}"

    def test_injection_in_password_field_fails_for_real_email(self, client):
        register(client)
        resp = login(client, email=EMAIL, password="' OR '1'='1' --")
        assert resp.status_code == 401

    def test_error_response_is_generic(self, client):
        """CLAUDE.md rule: no stack traces or DB details in user-facing errors."""
        register(client)
        resp = login(client, email="'; DROP TABLE users; --", password="x")
        body = resp.get_data(as_text=True).lower()
        for leak in ("sqlite", "traceback", "syntax error", "select "):
            assert leak not in body, f"error response leaks internals: {leak!r}"


class TestLoginRateLimit:
    def test_sixth_attempt_blocked_even_with_correct_password(self, client):
        register(client)

        for _ in range(5):
            resp = login(client, password="wrong-password")
            assert resp.status_code in (401, 429)

        resp = login(client)  # correct password, but account must now be blocked
        assert resp.status_code == 429, "rate limit did not trigger after 5 failures"
        with client.session_transaction() as sess:
            assert "user_id" not in sess

    def test_failed_attempts_below_threshold_do_not_block(self, client):
        register(client)

        for _ in range(4):
            login(client, password="wrong-password")

        resp = login(client)  # correct password on the 5th attempt: allowed
        assert resp.status_code in (200, 302)
