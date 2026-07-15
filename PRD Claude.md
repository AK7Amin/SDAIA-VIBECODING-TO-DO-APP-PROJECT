# PRD — Secure To-Do App (تطبيق إدارة مهام)
> One-page Product Requirements Document.
> Structure per slide 49 (Overview, Features, UX Flow, Constraints).
> Project scope per slides 87–90 of the SDAIA Vibe Coding workshop.

---

## 1. Overview (نظرة عامة)

**What:** A simple, secure To-Do web application where a registered user can create, view, edit, and delete their personal tasks.

**For whom:** Workshop participants / individual users who need a personal task tracker.

**Goal:** Not just "make it work" — **make it last safely**. The app is the vehicle for applying the full security + discipline cycle learned in the course (rules file, strict TDD, security review).

**Success definition:** App passes all 4 rubric items (slide 90) — rules file actually applied, at least one test written before its code, zero hardcoded secrets, one documented & fixed vulnerability.

## 2. Key Features (الميزات الرئيسية)

- **User Authentication** (mandatory per slide 87): register + login with email & password.
  - Passwords hashed with bcrypt — never plain text.
  - Rate limiting: temporary block after 5 failed login attempts.
- **Task CRUD:** add, list, edit, mark complete, delete tasks.
- **Input Form** with full server-side validation & sanitization (task title required, max length, no script injection).
- **Secure Data Storage:** tasks persist in a database; every task belongs to exactly one user; a user can only ever see/modify **their own** tasks (no IDOR).
- **Generic error handling:** user-facing errors never reveal stack traces or DB structure.

## 3. UX Flow (تجربة المستخدم)

1. Visitor lands on **Login / Register** page.
2. New user registers → redirected to login.
3. User logs in → session created → redirected to **My Tasks** dashboard.
4. Dashboard shows the user's task list with an **Add Task** form at the top.
5. Each task row: checkbox (complete), edit button, delete button (delete asks for confirmation).
6. Logout button ends the session and returns to login.
7. Any unauthenticated request to /tasks routes → redirect to login.

## 4. Technical Constraints (القيود التقنية)

**Stack (kept simple for the workshop):**
- Backend: Python (Flask) + SQL database (SQLite/PostgreSQL).
- Frontend: HTML/CSS/JS (or a minimal React page).
- Tests: pytest.

**Security constraints (from CLAUDE.md — non-negotiable):**
- All secrets in `.env` (git-ignored); no API keys/passwords in code.
- All SQL via prepared statements / parameterized queries.
- Session check on every task endpoint; ownership check on every task ID.
- No DELETE/UPDATE without an explicit WHERE clause.

**Process constraints (slides 88–89):**
- `CLAUDE.md` rules file exists in repo root **before** the first line of code.
- Strict TDD: RED → GREEN → REFACTOR, in order, for every feature (auth + task CRUD).
- Security tests included: SQL injection attempt, auth bypass attempt, rate-limit check.
- Mandatory human review gates before merge: (1) auth code, (2) DB mutations/migrations, (3) env/keys — Trust, but Verify.
- Run the security-review prompt (slide 81) on the final code; document **at least one vulnerability found and fixed**.

## 5. Deliverables (التسليم — slide 90)

- 5-minute demo: show CLAUDE.md rules, run one failing→passing TDD cycle live, present the discovered & fixed vulnerability, share the project link/files.

**Out of scope:** teams/sharing tasks, notifications, mobile app, password reset via email.
