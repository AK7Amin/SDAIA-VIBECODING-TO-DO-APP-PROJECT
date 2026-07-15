"""RED-phase tests for registration & login only (PRD §2, CLAUDE.md §1-2).

Three security guarantees are pinned down here, BEFORE any implementation:

  1. Passwords are stored as bcrypt hashes — never plain text.
  2. SQL-injection login attempts fail, leak nothing, create no session.
  3. After 5 failed logins the account is rate-limited (HTTP 429),
     even if the 6th attempt uses the correct password.

Contract these tests impose on the future app.py:
  - a create_app(config) factory accepting TESTING / DATABASE / SECRET_KEY
  - a `users` table with `email` and `password_hash` columns
  - POST /register and POST /login accepting form fields email + password
  - status codes: 201/302 register ok, 200/302 login ok, 401 bad
    credentials, 429 rate-limited
"""
import sqlite3
import time

import bcrypt
import pytest

import app as app_module

EMAIL = "user@example.com"
PASSWORD = "S3cure!passphrase"

# Classic injection payloads: always-true condition, table drop, comment-out.
SQL_INJECTION_PAYLOADS = [
    "' OR '1'='1' --",
    "'; DROP TABLE users; --",
    "admin' --",
]


def register(client, email=EMAIL, password=PASSWORD):
    return client.post("/register", data={"email": email, "password": password})


def login(client, email=EMAIL, password=PASSWORD):
    return client.post("/login", data={"email": email, "password": password})


def assert_no_session(client):
    with client.session_transaction() as sess:
        assert "user_id" not in sess, "a login session was created — it must not be"


# --- 1. Registration stores bcrypt, never plain text --------------------------


class TestRegistrationHashing:
    def test_register_succeeds(self, client):
        resp = register(client)
        assert resp.status_code in (201, 302)

    def test_stored_password_is_bcrypt_hash_not_plaintext(self, client, db_path):
        register(client)

        # Read the raw database file directly — the attacker's view of a stolen DB.
        con = sqlite3.connect(db_path)
        try:
            row = con.execute(
                "SELECT password_hash FROM users WHERE email = ?", (EMAIL,)
            ).fetchone()
        finally:
            con.close()

        assert row is not None, "no user row was created"
        stored = row[0].encode("utf-8") if isinstance(row[0], str) else row[0]

        assert stored != PASSWORD.encode("utf-8"), "password stored in PLAIN TEXT"
        assert stored.startswith(b"$2"), "not a bcrypt hash ($2a/$2b prefix missing)"
        assert bcrypt.checkpw(PASSWORD.encode("utf-8"), stored), (
            "stored hash does not verify against the original password"
        )


# --- 2. SQL-injection login attempts must fail ---------------------------------


class TestLoginSqlInjection:
    @pytest.mark.parametrize("payload", SQL_INJECTION_PAYLOADS)
    def test_injection_as_email_and_password_is_rejected(self, client, payload):
        register(client)
        resp = login(client, email=payload, password=payload)
        assert resp.status_code == 401, f"injection accepted: {payload!r}"
        assert_no_session(client)

    def test_injection_in_password_field_fails_for_real_email(self, client):
        register(client)
        resp = login(client, email=EMAIL, password="' OR '1'='1' --")
        assert resp.status_code == 401
        assert_no_session(client)

    def test_users_table_survives_drop_table_attempt(self, client, db_path):
        register(client)
        login(client, email="'; DROP TABLE users; --", password="x")

        con = sqlite3.connect(db_path)
        try:
            row = con.execute(
                "SELECT COUNT(*) FROM users"
            ).fetchone()  # raises if the table was dropped
        finally:
            con.close()
        assert row[0] == 1, "users table lost rows after injection attempt"

    def test_error_response_is_generic(self, client):
        """CLAUDE.md §1: errors must never expose internals to the user."""
        register(client)
        resp = login(client, email="'; DROP TABLE users; --", password="x")
        body = resp.get_data(as_text=True).lower()
        for leak in ("sqlite", "traceback", "syntax error", "select "):
            assert leak not in body, f"error response leaks internals: {leak!r}"


# --- 3. Rate limiting: exactly 5 failed attempts -------------------------------


class TestLoginRateLimit:
    def test_sixth_attempt_blocked_even_with_correct_password(self, client):
        register(client)

        for _ in range(5):
            resp = login(client, password="wrong-password")
            assert resp.status_code in (401, 429)

        # The lock must hold even when the attacker finally guesses right.
        resp = login(client)
        assert resp.status_code == 429, "no rate limit after 5 failed attempts"
        assert_no_session(client)

    def test_four_failures_do_not_block_a_fumbling_real_user(self, client):
        register(client)

        for _ in range(4):
            login(client, password="wrong-password")

        resp = login(client)  # correct password on attempt #5 — still allowed
        assert resp.status_code in (200, 302)


# --- Security fix #1: the lockout must be TEMPORARY (PRD: "temporary block") ---
#
# Vulnerability: a permanent lock lets an attacker who merely knows the
# victim's email fail 5 logins on purpose and lock the victim out FOREVER.
# The lock must expire, restoring access to the legitimate user.


def advance_time(monkeypatch, seconds):
    """Fake the app's clock: make app.now() report `seconds` in the future.

    raising=False so this is a no-op before the `now` seam exists (RED phase
    fails on behavior — still locked — not on plumbing).
    """
    target = time.time() + seconds
    monkeypatch.setattr(app_module, "now", lambda: target, raising=False)


class TestLockoutExpiry:
    def test_lock_expires_and_user_can_log_in_again(self, client, monkeypatch):
        register(client)
        for _ in range(5):
            login(client, password="wrong-password")
        assert login(client).status_code == 429  # locked, as designed

        # 15 minutes + 1 second later, the rightful owner must get back in.
        advance_time(monkeypatch, app_module.LOCKOUT_SECONDS + 1)
        resp = login(client)
        assert resp.status_code == 200, "lockout never expires — permanent DoS"

    def test_lock_still_holds_just_before_expiry(self, client, monkeypatch):
        register(client)
        for _ in range(5):
            login(client, password="wrong-password")

        # One minute before the window ends: still locked, even with the
        # correct password.
        advance_time(monkeypatch, app_module.LOCKOUT_SECONDS - 60)
        assert login(client).status_code == 429


# --- Security fix #3: password strength (Medium) ------------------------------


class TestPasswordStrength:
    def test_too_short_password_rejected(self, client):
        resp = register(client, email="new@example.com", password="short7!")  # 7 chars
        assert resp.status_code == 400

    def test_eight_char_password_accepted(self, client):
        resp = register(client, email="new@example.com", password="eightch8")  # exactly 8
        assert resp.status_code == 201

    def test_over_72_bytes_rejected(self, client):
        # bcrypt silently truncates at 72 bytes: a 100-char password would let
        # a different 100-char password with the same first 72 chars log in.
        resp = register(client, email="new@example.com", password="a" * 73)
        assert resp.status_code == 400


# --- Security fix #4: email format validation (Low) ---------------------------


class TestEmailValidation:
    @pytest.mark.parametrize(
        "bad_email",
        ["not-an-email", "missing@tld", "@no-local.com", "spaces in@email.com", "a" * 250 + "@x.com"],
    )
    def test_malformed_email_rejected(self, client, bad_email):
        resp = register(client, email=bad_email, password=PASSWORD)
        assert resp.status_code == 400, f"accepted bad email: {bad_email!r}"

    def test_valid_email_accepted(self, client):
        assert register(client, email="good.name@example.co", password=PASSWORD).status_code == 201


# --- Security fix #5: no user enumeration via timing (Low) --------------------


class TestTimingEnumeration:
    def test_unknown_email_still_runs_a_hash_check(self, client, monkeypatch):
        """A login for a non-existent email must still call bcrypt.checkpw,
        otherwise the faster response reveals which emails have accounts."""
        register(client)  # creates EMAIL

        calls = []
        real_checkpw = bcrypt.checkpw
        monkeypatch.setattr(
            bcrypt, "checkpw", lambda *a, **k: calls.append(1) or real_checkpw(*a, **k)
        )

        login(client, email="does-not-exist@example.com", password="whatever")
        assert calls, "no hash performed for unknown email — timing leak"


# --- Security fix #6: failed-login map must be bounded (Medium) ---------------
#
# The in-memory failed-login dict accepts ANY email, even unregistered ones.
# An attacker flooding logins with millions of unique fake emails would grow
# the dict without limit — a memory-exhaustion DoS. The map must stay bounded.


class TestFailedLoginMapBounded:
    def test_map_does_not_grow_without_bound(self, client, monkeypatch):
        # We're testing the map bound, not hashing — stub bcrypt so this
        # flood of thousands of logins runs in seconds, not minutes.
        monkeypatch.setattr(bcrypt, "checkpw", lambda *a, **k: False)
        failed = client.application.extensions["failed_logins"]

        for i in range(app_module.MAX_TRACKED_EMAILS + 200):
            login(client, email=f"flood{i}@example.com", password="x")

        assert len(failed) <= app_module.MAX_TRACKED_EMAILS, (
            f"map grew to {len(failed)} — unbounded, memory-DoS risk"
        )
