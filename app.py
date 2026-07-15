"""Secure To-Do app — GREEN phase: minimum code to pass tests/test_auth.py.

CLAUDE.md §1 rules applied here:
- Passwords: bcrypt-hashed before storage, never plain text.
- SQL: parameterized queries only — user input never concatenated into SQL.
- Rate limiting: login refused (429) after 5 failed attempts per email.
- Errors: generic messages only; internals never reach the client.
- Secrets: SECRET_KEY comes from the environment; the app refuses to start
  without one rather than falling back to a guessable default.
"""
import os
import sqlite3

import bcrypt
from flask import Flask, g, jsonify, request, session

MAX_FAILED_LOGINS = 5

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
);
"""


def create_app(config=None):
    app = Flask(__name__)
    app.config.update(
        DATABASE=os.environ.get("DATABASE", "todo.db"),
        SECRET_KEY=os.environ.get("SECRET_KEY", ""),
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

    register_routes(app)
    register_error_handlers(app)
    return app


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

        if not email or not password:
            return jsonify(error="Email and password are required."), 400

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
        # password must be refused.
        if failed.get(email, 0) >= MAX_FAILED_LOGINS:
            return jsonify(error="Too many attempts. Try again later."), 429

        db = get_db()
        row = db.execute(
            "SELECT id, password_hash FROM users WHERE email = ?", (email,)
        ).fetchone()

        ok = row is not None and bcrypt.checkpw(
            password.encode("utf-8"), row["password_hash"].encode("utf-8")
        )

        if not ok:
            failed[email] = failed.get(email, 0) + 1
            # Same message whether the email exists or the password is wrong.
            return jsonify(error="Invalid email or password."), 401

        failed.pop(email, None)
        session.clear()
        session["user_id"] = row["id"]
        return jsonify(message="Logged in."), 200

    @app.post("/logout")
    def logout():
        session.clear()
        return jsonify(message="Logged out."), 200


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
