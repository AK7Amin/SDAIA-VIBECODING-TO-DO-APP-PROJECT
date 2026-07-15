"""Shared test fixtures.

Every test gets a fresh app wired to a throwaway SQLite database, plus a
test client (a fake browser). The import below is the point of the RED
phase: app.py does not exist yet, so the whole suite fails on collection.
"""
import os
import tempfile

import pytest

from app import create_app  # RED: no app.py yet — this import fails by design


@pytest.fixture
def app():
    """A fresh app instance backed by a temporary database, deleted afterwards."""
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    app = create_app(
        {
            "TESTING": True,
            "DATABASE": db_path,
            "SECRET_KEY": "test-only-secret",  # for tests only; real runs use .env
        }
    )
    yield app
    os.close(db_fd)
    os.unlink(db_path)


@pytest.fixture
def client(app):
    """A fake browser: can POST forms and carries session cookies between calls."""
    return app.test_client()


@pytest.fixture
def db_path(app):
    """Path to the raw SQLite file, so tests can inspect what was really stored."""
    return app.config["DATABASE"]
