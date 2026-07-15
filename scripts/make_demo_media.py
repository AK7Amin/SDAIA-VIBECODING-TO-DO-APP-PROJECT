"""Generate README media: docs/login.png, docs/dashboard.png, docs/demo.gif.

Runs the app on a throwaway database, drives it with Playwright (using the
system Edge browser, headless) through the full user journey, and assembles
the captured frames into an animated GIF with Pillow.

Usage:
    pip install playwright pillow
    python scripts/make_demo_media.py
"""
import io
import sys
import tempfile
import threading
from pathlib import Path

from PIL import Image
from playwright.sync_api import sync_playwright
from werkzeug.serving import make_server

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from app import create_app  # noqa: E402

PORT = 5001
BASE = f"http://127.0.0.1:{PORT}"
DOCS = REPO_ROOT / "docs"

EMAIL = "demo@todo.app"
PASSWORD = "Demo!passphrase9"

frames = []


def start_server():
    db_path = tempfile.mkstemp(suffix=".db")[1]
    app = create_app({"DATABASE": db_path, "SECRET_KEY": "demo-only-secret"})
    server = make_server("127.0.0.1", PORT, app)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def snap(page, save_as=None, hold=1):
    """Capture a frame for the GIF; optionally also save it as a PNG."""
    png = page.screenshot()
    if save_as:
        (DOCS / save_as).write_bytes(png)
    for _ in range(hold):  # hold > 1 keeps the frame on screen longer
        frames.append(png)


def add_task(page, title, priority="2", due_date=""):
    page.fill("#new-title", title)
    page.select_option("#new-priority", priority)
    if due_date:
        page.fill("#new-due", due_date)
    page.click("#add-form button")
    page.wait_for_timeout(300)


def main():
    DOCS.mkdir(exist_ok=True)
    server = start_server()

    with sync_playwright() as p:
        browser = p.chromium.launch(channel="msedge", headless=True)
        page = browser.new_page(viewport={"width": 1000, "height": 650})
        page.on("dialog", lambda d: d.accept())  # auto-confirm the delete dialog

        # 1. Login page
        page.goto(f"{BASE}/login")
        snap(page, save_as="login.png", hold=2)

        # 2. Register
        page.click('.tab[data-tab="register"]')
        page.fill("#register-form input[name=email]", EMAIL)
        page.fill("#register-form input[name=password]", PASSWORD)
        snap(page)
        page.click("#register-form button")
        page.wait_for_timeout(400)
        snap(page)  # "Registered! Please log in."

        # 3. Log in
        page.fill("#login-form input[name=email]", EMAIL)
        page.fill("#login-form input[name=password]", PASSWORD)
        snap(page)
        page.click("#login-form button")
        page.wait_for_url(f"{BASE}/dashboard")
        page.wait_for_timeout(300)
        snap(page)  # empty dashboard

        # 4. Add tasks with different priorities and due dates (shows badges)
        add_task(page, "Submit the workshop project", priority="3", due_date="2026-07-10")
        snap(page)
        add_task(page, "Review the security fixes", priority="3", due_date="2026-07-15")
        add_task(page, "Plan next sprint", priority="2", due_date="2026-09-01")
        add_task(page, "Read about CSP headers", priority="1")
        snap(page, save_as="dashboard.png", hold=2)

        # 5. Complete the first task
        page.locator("li input[type=checkbox]").first.check()
        page.wait_for_timeout(300)
        snap(page, hold=2)

        # 6. Delete the last task (confirm dialog auto-accepted)
        page.locator("li button.delete").last.click()
        page.wait_for_timeout(300)
        snap(page, hold=2)

        # 7. Log out
        page.click("#logout")
        page.wait_for_url(f"{BASE}/login")
        snap(page, hold=2)

        browser.close()

    server.shutdown()

    images = [Image.open(io.BytesIO(f)).convert("P", palette=Image.ADAPTIVE) for f in frames]
    images[0].save(
        DOCS / "demo.gif",
        save_all=True,
        append_images=images[1:],
        duration=1100,
        loop=0,
        optimize=True,
    )
    for name in ("login.png", "dashboard.png", "demo.gif"):
        size_kb = (DOCS / name).stat().st_size // 1024
        print(f"{name}: {size_kb} KB")


if __name__ == "__main__":
    main()
