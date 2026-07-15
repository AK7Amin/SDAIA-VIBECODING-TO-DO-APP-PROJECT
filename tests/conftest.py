"""Shared fixtures. Tests import create_app from app.py — which does NOT exist yet (RED phase)."""
import os
import tempfile

import pytest

from app import create_app


@pytest.fixture
def app():
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    app = create_app(
        {
            "TESTING": True,
            "DATABASE": db_path,
            "SECRET_KEY": "test-only-secret",  # test fixture only, never used in production
        }
    )
    yield app
    os.close(db_fd)
    os.unlink(db_path)


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def db_path(app):
    return app.config["DATABASE"]
