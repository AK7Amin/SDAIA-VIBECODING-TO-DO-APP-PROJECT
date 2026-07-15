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

from functools import wraps

import bcrypt
from dotenv import load_dotenv
from flask import Flask, g, jsonify, redirect, render_template, request, session

load_dotenv()  # reads .env into the environment; .env is git-ignored, never committed

MAX_FAILED_LOGINS = 5

MAX_TITLE_LENGTH = 200

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
    register_task_routes(app)
    register_page_routes(app)
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
