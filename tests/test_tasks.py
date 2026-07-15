"""RED-phase tests for task CRUD (PRD §2-3, CLAUDE.md §1-2).

Guarantees pinned down BEFORE implementation:

  1. Every /tasks route requires login — unauthenticated requests are
     redirected to /login (PRD UX flow item 7).
  2. Full CRUD: create, list, update, mark complete, delete.
  3. Validation: title required, max 200 chars, HTML/script tags rejected.
  4. IDOR protection: a user can never see, modify, or delete another
     user's task — foreign task ids answer 404, as if they don't exist.

Contract imposed on app.py:
  - GET  /tasks              -> 200, JSON list of {id, title, completed}
  - POST /tasks  (form)      -> 201, JSON of the created task
  - PATCH /tasks/<id> (form) -> 200, fields: title and/or completed ("0"/"1")
  - DELETE /tasks/<id>       -> 200
  - not logged in            -> 302 redirect containing /login
  - someone else's task id   -> 404
"""
ALICE = ("alice@example.com", "Alice!passphrase1")
BOB = ("bob@example.com", "Bob!passphrase22")

MAX_TITLE_LENGTH = 200


def signup_and_login(client, who):
    email, password = who
    client.post("/register", data={"email": email, "password": password})
    resp = client.post("/login", data={"email": email, "password": password})
    assert resp.status_code == 200, "fixture login failed"


def create_task(client, title="Buy milk"):
    return client.post("/tasks", data={"title": title})


def list_tasks(client):
    resp = client.get("/tasks")
    assert resp.status_code == 200
    return resp.get_json()


# --- 1. No login, no tasks ----------------------------------------------------


class TestAuthRequired:
    def test_all_task_routes_redirect_anonymous_users_to_login(self, client):
        attempts = [
            client.get("/tasks"),
            client.post("/tasks", data={"title": "sneaky"}),
            client.patch("/tasks/1", data={"title": "sneaky"}),
            client.delete("/tasks/1"),
        ]
        for resp in attempts:
            assert resp.status_code == 302, f"anonymous request not redirected"
            assert "/login" in resp.headers.get("Location", "")


# --- 2. CRUD basics -----------------------------------------------------------


class TestTaskCrud:
    def test_create_returns_the_task(self, client):
        signup_and_login(client, ALICE)
        resp = create_task(client, "Buy milk")
        assert resp.status_code == 201
        task = resp.get_json()
        assert task["title"] == "Buy milk"
        assert task["completed"] is False
        assert isinstance(task["id"], int)

    def test_list_returns_own_tasks(self, client):
        signup_and_login(client, ALICE)
        create_task(client, "Task one")
        create_task(client, "Task two")
        titles = [t["title"] for t in list_tasks(client)]
        assert titles == ["Task one", "Task two"]

    def test_update_title(self, client):
        signup_and_login(client, ALICE)
        task_id = create_task(client, "Old title").get_json()["id"]

        resp = client.patch(f"/tasks/{task_id}", data={"title": "New title"})
        assert resp.status_code == 200
        assert [t["title"] for t in list_tasks(client)] == ["New title"]

    def test_mark_complete(self, client):
        signup_and_login(client, ALICE)
        task_id = create_task(client).get_json()["id"]

        resp = client.patch(f"/tasks/{task_id}", data={"completed": "1"})
        assert resp.status_code == 200
        assert list_tasks(client)[0]["completed"] is True

    def test_delete_removes_the_task(self, client):
        signup_and_login(client, ALICE)
        task_id = create_task(client).get_json()["id"]

        resp = client.delete(f"/tasks/{task_id}")
        assert resp.status_code == 200
        assert list_tasks(client) == []


# --- 3. Input validation (CLAUDE.md: validate & sanitize everything) ----------


class TestTaskValidation:
    def test_empty_title_rejected(self, client):
        signup_and_login(client, ALICE)
        assert create_task(client, "").status_code == 400
        assert create_task(client, "   ").status_code == 400

    def test_title_over_max_length_rejected(self, client):
        signup_and_login(client, ALICE)
        assert create_task(client, "x" * (MAX_TITLE_LENGTH + 1)).status_code == 400
        assert create_task(client, "x" * MAX_TITLE_LENGTH).status_code == 201

    def test_script_tag_in_title_rejected(self, client):
        signup_and_login(client, ALICE)
        resp = create_task(client, "<script>alert('xss')</script>")
        assert resp.status_code == 400, "HTML in a task title must be rejected"
        assert list_tasks(client) == []

    def test_update_validated_like_create(self, client):
        signup_and_login(client, ALICE)
        task_id = create_task(client, "Fine title").get_json()["id"]

        assert client.patch(f"/tasks/{task_id}", data={"title": ""}).status_code == 400
        assert (
            client.patch(f"/tasks/{task_id}", data={"title": "<b>bold</b>"}).status_code
            == 400
        )
        # Failed updates must not have changed anything.
        assert [t["title"] for t in list_tasks(client)] == ["Fine title"]


# --- 4. IDOR: your tasks are invisible to everyone else ------------------------


class TestIdorProtection:
    def _two_users_one_task(self, app):
        """Alice owns a task; Bob is logged in on a separate client."""
        alice = app.test_client()
        signup_and_login(alice, ALICE)
        task_id = create_task(alice, "Alice's secret plan").get_json()["id"]

        bob = app.test_client()
        signup_and_login(bob, BOB)
        return alice, bob, task_id

    def test_list_never_shows_other_users_tasks(self, app):
        alice, bob, _ = self._two_users_one_task(app)
        assert list_tasks(bob) == []

    def test_cannot_read_or_update_another_users_task(self, app):
        alice, bob, task_id = self._two_users_one_task(app)

        resp = bob.patch(f"/tasks/{task_id}", data={"title": "hacked"})
        assert resp.status_code == 404, "foreign task must look like it doesn't exist"
        # Alice's task is untouched.
        assert [t["title"] for t in list_tasks(alice)] == ["Alice's secret plan"]

    def test_cannot_delete_another_users_task(self, app):
        alice, bob, task_id = self._two_users_one_task(app)

        resp = bob.delete(f"/tasks/{task_id}")
        assert resp.status_code == 404
        assert len(list_tasks(alice)) == 1, "Alice's task was deleted by Bob!"

    def test_cannot_mark_another_users_task_complete(self, app):
        alice, bob, task_id = self._two_users_one_task(app)

        resp = bob.patch(f"/tasks/{task_id}", data={"completed": "1"})
        assert resp.status_code == 404
        assert list_tasks(alice)[0]["completed"] is False
