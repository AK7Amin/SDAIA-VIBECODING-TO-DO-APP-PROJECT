# Security Review — Step 8 (slide 81)

> ملخص: مراجعة أمنية كاملة للكود كشفت **7 ثغرات** (اثنتان High، ثلاث Medium، اثنتان Low) — **كلها أُصلحت** بأسلوب TDD (اختبار فاشل يثبت الثغرة ← إصلاح ← اختبار ناجح). المتبقي بنود خارج نطاق الورشة فقط (CSP صارمة، حد لكل IP، خادم الإنتاج).

Full review of the codebase against: SQL injection, XSS, CSRF, exposed
secrets, unvalidated input, unprotected endpoints.

## What was checked and found SAFE

| Area | Verdict | Evidence |
|---|---|---|
| SQL injection | ✅ | All 8 queries parameterized (`?`); proven by `tests/test_auth.py::TestLoginSqlInjection` incl. a `DROP TABLE` survival test |
| XSS | ✅ | Titles containing `<`/`>` rejected server-side before storage; UI renders only via `textContent`, never `innerHTML` |
| Password storage | ✅ | bcrypt with per-user salt; test reads the raw DB file and verifies the `$2` hash |
| Exposed secrets | ✅ | `SECRET_KEY` from git-ignored `.env`; app refuses to start without it; no keys in the repo |
| IDOR | ✅ | Every task query scoped `AND user_id = ?`; 4 dedicated tests (list/update/complete/delete against a foreign task → 404) |
| Error leakage | ✅ | Generic messages only; `debug=False`; silent 500 handler; login failure message identical for wrong-email vs wrong-password |

## Vulnerability #1 — Permanent account lockout (High) — FIXED

- **Found in:** `app.py` `/login` — the failed-attempt counter never expired.
- **Attack:** anyone who knows the victim's **email only** submits 5 wrong
  passwords on purpose → the victim is locked out **forever** (until a server
  restart). A trivial, repeatable denial of service on any account. The PRD
  explicitly requires a *temporary* block.
- **Proof (RED):** `tests/test_auth.py::TestLockoutExpiry` — fast-forwards the
  clock past the lockout window and asserts the rightful owner gets back in.
  Failed against the old code (429 forever).
- **Fix (GREEN):** failed-login entries are now `{count, locked_until}`;
  a lock expires after **15 minutes** (`LOCKOUT_SECONDS`), after which the
  email gets a clean slate. A `now()` seam lets tests fake the clock.
- **Commit:** `a89fa82`.

## Vulnerability #2 — No CSRF protection (High) — FIXED

- **Found in:** all state-changing routes; session cookie had no hardening flags.
- **Attack:** the session lives in a cookie, and browsers attach cookies
  automatically. A malicious page on another site auto-submits a
  form-encoded `POST /tasks` (or `/logout`, `/register`) from the victim's
  browser — the cookie rides along and the app executed it. Verified live
  before the fix: a token-less forged request returned **201 Created**.
- **Proof (RED):** `tests/test_csrf.py` — 6 tests: no token → 403, wrong
  token → 403, valid token → full flow works, cookie flags present, page
  embeds the token. All 6 failed against the old code.
- **Fix (GREEN):**
  - `before_request` guard: every `POST/PATCH/PUT/DELETE` must echo the
    session's CSRF token in the `X-CSRF-Token` header (or `csrf_token`
    form field); compared with `hmac.compare_digest` (constant-time).
  - Session cookie now `SameSite=Lax` + `HttpOnly` (defense in depth:
    cross-site sends blocked by the browser AND token required AND cookie
    unreadable from JS).
  - Token minted per session, **rotated on login**, delivered to pages via
    `<meta name="csrf-token">`, attached by `fetch()` in both templates.
- **Verified live in the browser after the fix:** forged fetch → **403**,
  legit fetch → **201**, `document.cookie` returns empty (HttpOnly works).
- **Commit:** `06a27c2`.

## Findings 3-7 — all FIXED in Phase 1 (each via TDD)

| # | Finding | Severity | Fix | Commit |
|---|---|---|---|---|
| 3 | Password strength: a 1-char password was accepted | Medium | `validate_credentials()` requires ≥ 8 chars, rejects > 72 bytes (bcrypt truncation) | `2e5c0c2` |
| 4 | Email format not validated server-side | Low | regex + length ≤ 254 on register | `2e5c0c2` |
| 5 | User enumeration via timing: unknown email skipped bcrypt (faster reply) | Low | `/login` always runs `bcrypt.checkpw` against a dummy hash when the email is unknown | `2e5c0c2` |
| 6 | Failed-login map unbounded (memory DoS via fake emails) | Medium | `prune_failed_logins()` caps the map at 10k and sweeps expired locks | `a06d982` |
| 7 | No security headers | Medium | `after_request` adds `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy` | `a06d982` |

## Remaining (out of scope / deferred)

| # | Finding | Severity | Note |
|---|---|---|---|
| 8 | No strict Content-Security-Policy | Low | Deferred: a strict CSP needs the inline JS/CSS moved to static files first. The three headers above are in place today. |
| 9 | Per-IP rate limiting | Low | Current limit is per-email; low-and-slow spraying across many accounts is still uncounted. Would need a per-IP counter. |
| 10 | Flask dev server + SQLite | Info | Workshop scope by design; use a WSGI server + managed DB for real deployment. |
