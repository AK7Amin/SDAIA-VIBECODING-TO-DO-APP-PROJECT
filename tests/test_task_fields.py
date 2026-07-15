"""RED-phase tests for Phase 2: due dates + priority on tasks.

Guarantees pinned down BEFORE implementation:

  1. A task carries `due_date` (ISO yyyy-mm-dd or null) and `priority`
     (1=low, 2=normal, 3=high; default 2), returned in its JSON.
  2. Validation: malformed dates and out-of-range priorities are rejected
     (400) on both create and update.
  3. Ordering: active tasks before completed; then higher priority first;
     then earlier due date first; tasks without a due date come last.
  4. IDOR still holds: the new fields don't open any cross-user access.

Contract imposed on app.py:
  - POST /tasks accepts optional `due_date` and `priority` form fields
  - task JSON gains "due_date" (str|None) and "priority" (int) keys
  - PATCH /tasks/<id> can update either field, with the same validation
"""
EMAIL = "owner@example.com"
PASSWORD = "Owner!passphrase1"


def signup_and_login(client, email=EMAIL, password=PASSWORD):
    client.post("/register", data={"email": email, "password": password})
    assert client.post("/login", data={"email": email, "password": password}).status_code == 200


def create(client, title="Task", **fields):
    return client.post("/tasks", data={"title": title, **fields})


def list_tasks(client):
    resp = client.get("/tasks")
    assert resp.status_code == 200
    return resp.get_json()


# --- 1. New fields exist with sensible defaults --------------------------------


class TestNewFieldsPresent:
    def test_task_json_has_due_date_and_priority(self, client):
        signup_and_login(client)
        task = create(client, "Plain task").get_json()
        assert task["due_date"] is None       # no date given -> null
        assert task["priority"] == 2          # default = normal

    def test_create_accepts_due_date_and_priority(self, client):
        signup_and_login(client)
        task = create(client, "Full task", due_date="2026-08-01", priority="3").get_json()
        assert task["due_date"] == "2026-08-01"
        assert task["priority"] == 3


# --- 2. Validation -------------------------------------------------------------


class TestFieldValidation:
    def test_bad_due_date_rejected(self, client):
        signup_and_login(client)
        for bad in ("01-08-2026", "2026-13-01", "not-a-date", "2026/08/01"):
            assert create(client, "x", due_date=bad).status_code == 400, f"accepted {bad!r}"

    def test_priority_out_of_range_rejected(self, client):
        signup_and_login(client)
        for bad in ("0", "4", "-1", "high"):
            assert create(client, "x", priority=bad).status_code == 400, f"accepted {bad!r}"

    def test_update_validates_new_fields(self, client):
        signup_and_login(client)
        tid = create(client, "Task").get_json()["id"]
        assert client.patch(f"/tasks/{tid}", data={"due_date": "nope"}).status_code == 400
        assert client.patch(f"/tasks/{tid}", data={"priority": "9"}).status_code == 400
        # A valid update works and is reflected.
        assert client.patch(f"/tasks/{tid}", data={"priority": "3"}).status_code == 200
        assert list_tasks(client)[0]["priority"] == 3


# --- 3. Smart ordering ---------------------------------------------------------


class TestOrdering:
    def test_active_high_priority_earliest_due_comes_first(self, client):
        signup_and_login(client)
        create(client, "Low, no date", priority="1")
        create(client, "High, due later", priority="3", due_date="2026-12-01")
        create(client, "High, due soon", priority="3", due_date="2026-08-01")
        create(client, "Normal", priority="2")

        titles = [t["title"] for t in list_tasks(client)]
        # High priority first, and among the two highs the sooner due date wins.
        assert titles[0] == "High, due soon"
        assert titles[1] == "High, due later"
        assert titles[2] == "Normal"
        assert titles[3] == "Low, no date"

    def test_completed_tasks_sink_to_the_bottom(self, client):
        signup_and_login(client)
        done_id = create(client, "Done high", priority="3").get_json()["id"]
        create(client, "Active low", priority="1")
        client.patch(f"/tasks/{done_id}", data={"completed": "1"})

        titles = [t["title"] for t in list_tasks(client)]
        assert titles == ["Active low", "Done high"], "completed task must sink below active"


# --- 4. IDOR still holds with the new fields -----------------------------------


class TestIdorStillHolds:
    def test_cannot_set_priority_on_another_users_task(self, app):
        alice = app.test_client()
        signup_and_login(alice, "alice@example.com", "Alice!passphrase1")
        tid = create(alice, "Alice task", priority="1").get_json()["id"]

        bob = app.test_client()
        signup_and_login(bob, "bob@example.com", "Bob!passphrase222")
        resp = bob.patch(f"/tasks/{tid}", data={"priority": "3"})
        assert resp.status_code == 404
        assert list_tasks(alice)[0]["priority"] == 1, "Bob changed Alice's task!"
