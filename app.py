"""Secure To-Do app — GREEN phase: minimum code to pass tests/test_auth.py.

CLAUDE.md §1 rules applied here:
- Passwords: bcrypt-hashed before storage, never plain text.
- SQL: parameterized queries only — user input never concatenated into SQL.
- Rate limiting: login refused (429) after 5 failed attempts per email.
- Errors: generic messages only; internals never reach the client.
- Secrets: SECRET_KEY comes from the environment; the app refuses to start
  without one rather than falling back to a guessable default.
"""
import hmac
import os
import re
import secrets
import sqlite3
import time

from functools import wraps

import bcrypt
from dotenv import load_dotenv
from flask import Flask, g, jsonify, redirect, render_template, request, session

load_dotenv()  # reads .env into the environment; .env is git-ignored, never committed

MAX_FAILED_LOGINS = 5
LOCKOUT_SECONDS = 15 * 60  # PRD requires a TEMPORARY block, not a permanent one
MAX_TRACKED_EMAILS = 10_000  # cap the failed-login map so it can't exhaust memory

# Security headers added to every response (defense in depth). A strict
# Content-Security-Policy is intentionally deferred to Phase 3, after inline
# JS/CSS is moved to static files (a strict CSP would break inline scripts).
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",   # don't let the browser guess content types
    "X-Frame-Options": "DENY",             # can't be embedded in a frame (clickjacking)
    "Referrer-Policy": "same-origin",      # don't leak our URLs to other sites
}

MAX_TITLE_LENGTH = 200

MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_BYTES = 72  # bcrypt silently truncates beyond this — reject instead
MAX_EMAIL_LENGTH = 254   # RFC 5321 practical maximum
# Deliberately simple: exactly one @, non-empty local part, a dotted domain,
# and no spaces. Not RFC-perfect, but enough to reject obvious garbage.
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# A fixed bcrypt hash of a throwaway password. When a login targets an email
# that doesn't exist, we still run checkpw against THIS, so the response takes
# the same time as a real (but wrong-password) login — no user enumeration.
_DUMMY_HASH = bcrypt.hashpw(b"dummy-password-for-timing", bcrypt.gensalt())


def now():
    """Current time — a seam so tests can fast-forward the clock."""
    return time.time()


def prune_failed_logins(failed):
    """Keep the failed-login map bounded: drop expired locks, and if still
    over the cap, evict the oldest-tracked emails. Prevents a flood of fake
    emails from growing the map without limit (memory-DoS)."""
    current = now()
    expired = [
        email
        for email, entry in failed.items()
        if entry["locked_until"] is not None and current >= entry["locked_until"]
    ]
    for email in expired:
        failed.pop(email, None)

    # Dicts keep insertion order; pop from the front (oldest) until under cap.
    while len(failed) > MAX_TRACKED_EMAILS:
        oldest = next(iter(failed))
        failed.pop(oldest, None)


def validate_credentials(email, password):
    """Return an error string if the email/password are unacceptable, else None."""
    if not email or not password:
        return "Email and password are required."
    if len(email) > MAX_EMAIL_LENGTH or not EMAIL_RE.match(email):
        return "Enter a valid email address."
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        return f"Password must be at most {MAX_PASSWORD_BYTES} bytes."
    return None

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tasks (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id   INTEGER NOT NULL REFERENCES users(id),
    title     TEXT NOT NULL,
    completed INTEGER NOT NULL DEFAULT 0
);
"""


def create_app(config=None):
    app = Flask(__name__)
    app.config.update(
        DATABASE=os.environ.get("DATABASE", "todo.db"),
        SECRET_KEY=os.environ.get("SECRET_KEY", ""),
        # Session cookie hardening: unreadable from page JS, and never sent
        # on cross-site requests initiated by other origins.
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        CSRF_ENABLED=True,  # tests for OTHER features may switch this off
    )
    if config:
        app.config.update(config)

    if not app.config["SECRET_KEY"]:
        raise RuntimeError(
            "SECRET_KEY is not set. Put it in your environment (.env) — "
            "never hardcode it."
        )

    # Failed-login counter, per app instance: {email: count}. In-memory is
    # enough for the workshop; production would use a shared store (Redis).
    app.extensions["failed_logins"] = {}

    # Note: sqlite3's `with` only commits, it does NOT close — close explicitly,
    # or the leaked handle keeps the .db file locked on Windows.
    con = sqlite3.connect(app.config["DATABASE"])
    try:
        con.executescript(SCHEMA)
    finally:
        con.close()

    @app.teardown_appcontext
    def close_db(exc):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    @app.after_request
    def add_security_headers(response):
        for header, value in SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        return response

    register_csrf_protection(app)
    register_routes(app)
    register_task_routes(app)
    register_page_routes(app)
    register_error_handlers(app)
    return app


def get_csrf_token():
    """The session's CSRF token, minted on first use."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def register_csrf_protection(app):
    """Double-submit CSRF defense: every state-changing request must echo the
    session's token (X-CSRF-Token header or csrf_token form field). A forged
    cross-site request carries the cookie but cannot know the token."""

    @app.before_request
    def enforce_csrf():
        if not app.config["CSRF_ENABLED"]:
            return None
        if request.method not in ("POST", "PATCH", "DELETE", "PUT"):
            return None
        sent = (
            request.headers.get("X-CSRF-Token")
            or request.form.get("csrf_token")
            or ""
        )
        expected = session.get("csrf_token", "")
        # compare_digest: constant-time comparison, no timing leaks.
        if not expected or not hmac.compare_digest(sent, expected):
            return jsonify(error="Invalid or missing CSRF token."), 403
        return None

    @app.context_processor
    def inject_csrf_token():
        # Templates embed the token in a <meta> tag; page JS sends it back.
        return {"csrf_token": get_csrf_token}


def get_db():
    """One SQLite connection per request, closed automatically afterwards."""
    if "db" not in g:
        from flask import current_app

        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


def register_routes(app):
    @app.post("/register")
    def register():
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""

        error = validate_credentials(email, password)
        if error:
            return jsonify(error=error), 400

        pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (email, password_hash) VALUES (?, ?)",
                (email, pw_hash.decode("utf-8")),
            )
            db.commit()
        except sqlite3.IntegrityError:
            # Duplicate email — deliberately vague so attackers cannot
            # enumerate which emails have accounts.
            return jsonify(error="Registration failed."), 400

        return jsonify(message="Registered."), 201

    @app.post("/login")
    def login():
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""

        failed = app.extensions["failed_logins"]

        # Check the lock BEFORE the password: once locked, even the correct
        # password must be refused — but only until the lock EXPIRES.
        entry = failed.get(email)
        if entry and entry["locked_until"] is not None:
            if now() < entry["locked_until"]:
                return jsonify(error="Too many attempts. Try again later."), 429
            # Lock expired: clean slate for this email.
            failed.pop(email, None)

        db = get_db()
        row = db.execute(
            "SELECT id, password_hash FROM users WHERE email = ?", (email,)
        ).fetchone()

        # Always run a hash check — against the real hash if the user exists,
        # else against a dummy — so both paths take the same time (no timing
        # side-channel revealing which emails are registered).
        stored_hash = row["password_hash"].encode("utf-8") if row else _DUMMY_HASH
        password_ok = bcrypt.checkpw(password.encode("utf-8"), stored_hash)
        ok = row is not None and password_ok

        if not ok:
            entry = failed.setdefault(email, {"count": 0, "locked_until": None})
            entry["count"] += 1
            if entry["count"] >= MAX_FAILED_LOGINS:
                entry["locked_until"] = now() + LOCKOUT_SECONDS
            prune_failed_logins(failed)  # keep the map bounded (memory-DoS guard)
            # Same message whether the email exists or the password is wrong.
            return jsonify(error="Invalid email or password."), 401

        failed.pop(email, None)
        session.clear()
        session["user_id"] = row["id"]
        # Fresh CSRF token for the new session (rotation on privilege change).
        session["csrf_token"] = secrets.token_hex(32)
        return jsonify(message="Logged in."), 200

    @app.post("/logout")
    def logout():
        session.clear()
        return jsonify(message="Logged out."), 200


def register_page_routes(app):
    """HTML pages (login/register screen, task dashboard) for the browser demo.

    These are separate from the /register, /login, /tasks JSON API above —
    they just serve the pages that call that API with fetch().
    """

    @app.get("/")
    def index():
        return redirect("/dashboard" if "user_id" in session else "/login")

    @app.get("/login")
    def login_page():
        if "user_id" in session:
            return redirect("/dashboard")
        return render_template("login.html")

    @app.get("/dashboard")
    @login_required
    def dashboard_page():
        return render_template("dashboard.html")


def login_required(view):
    """Reject anonymous requests: redirect to /login (PRD UX flow item 7)."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/login")
        return view(*args, **kwargs)

    return wrapped


def validate_title(title):
    """Return (clean_title, error). Title: required, max length, no HTML."""
    title = (title or "").strip()
    if not title:
        return None, "Title is required."
    if len(title) > MAX_TITLE_LENGTH:
        return None, f"Title must be at most {MAX_TITLE_LENGTH} characters."
    if "<" in title or ">" in title:
        # Reject rather than escape: no HTML ever enters the database,
        # so nothing can leak unescaped into a page later (XSS).
        return None, "Title contains invalid characters."
    return title, None


def task_to_json(row):
    return {"id": row["id"], "title": row["title"], "completed": bool(row["completed"])}


def register_task_routes(app):
    @app.get("/tasks")
    @login_required
    def list_tasks():
        rows = get_db().execute(
            "SELECT id, title, completed FROM tasks WHERE user_id = ? ORDER BY id",
            (session["user_id"],),
        ).fetchall()
        return jsonify([task_to_json(r) for r in rows]), 200

    @app.post("/tasks")
    @login_required
    def create_task():
        title, error = validate_title(request.form.get("title"))
        if error:
            return jsonify(error=error), 400

        db = get_db()
        cur = db.execute(
            "INSERT INTO tasks (user_id, title, completed) VALUES (?, ?, 0)",
            (session["user_id"], title),
        )
        db.commit()
        return jsonify(id=cur.lastrowid, title=title, completed=False), 201

    @app.patch("/tasks/<int:task_id>")
    @login_required
    def update_task(task_id):
        db = get_db()
        # Ownership check: the id is only looked up WITH user_id, so another
        # user's task answers 404 — exactly as if it doesn't exist (no IDOR).
        row = db.execute(
            "SELECT id, title, completed FROM tasks WHERE id = ? AND user_id = ?",
            (task_id, session["user_id"]),
        ).fetchone()
        if row is None:
            return jsonify(error="Not found."), 404

        new_title = row["title"]
        if "title" in request.form:
            new_title, error = validate_title(request.form.get("title"))
            if error:
                return jsonify(error=error), 400

        new_completed = row["completed"]
        if "completed" in request.form:
            value = (request.form.get("completed") or "").strip().lower()
            if value not in ("0", "1", "true", "false"):
                return jsonify(error="Invalid value for completed."), 400
            new_completed = 1 if value in ("1", "true") else 0

        db.execute(
            "UPDATE tasks SET title = ?, completed = ? WHERE id = ? AND user_id = ?",
            (new_title, new_completed, task_id, session["user_id"]),
        )
        db.commit()
        return jsonify(id=task_id, title=new_title, completed=bool(new_completed)), 200

    @app.delete("/tasks/<int:task_id>")
    @login_required
    def delete_task(task_id):
        db = get_db()
        # Explicit WHERE with BOTH id and owner (CLAUDE.md: no DELETE without
        # explicit WHERE). rowcount 0 means not yours / not there: 404.
        cur = db.execute(
            "DELETE FROM tasks WHERE id = ? AND user_id = ?",
            (task_id, session["user_id"]),
        )
        db.commit()
        if cur.rowcount == 0:
            return jsonify(error="Not found."), 404
        return jsonify(message="Deleted."), 200


def register_error_handlers(app):
    @app.errorhandler(404)
    def not_found(exc):
        return jsonify(error="Not found."), 404

    @app.errorhandler(500)
    def server_error(exc):
        # Generic on purpose — no stack traces or DB details to the client.
        return jsonify(error="An internal error occurred."), 500


if __name__ == "__main__":
    create_app().run(debug=False)
