# Security Review — Step 8 (slide 81)

> ملخص: مراجعة أمنية كاملة للكود كشفت ثغرتين بخطورة High — قفلُ حسابٍ دائم يمكّن المهاجم من حجب الضحية، وغيابُ حماية CSRF. أُصلحتا كلتاهما بأسلوب TDD (اختبار فاشل يثبت الثغرة ← إصلاح ← اختبار ناجح) في الكومِتين `a89fa82` و `06a27c2`.

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

## Remaining findings (documented, not yet fixed)

| # | Finding | Severity | Suggested fix |
|---|---|---|---|
| 3 | Failed-login map unbounded (memory DoS via fake emails); limit is per-email only, so low-and-slow password spraying across many accounts is uncounted | Medium | Cap map size + periodic sweep of expired entries; add a per-IP limit |
| 4 | No password strength minimum (a 1-character password is accepted) | Medium | Require ≥ 8 chars; reject > 72 bytes (bcrypt truncation limit) |
| 5 | No security headers (`X-Content-Type-Options`, `X-Frame-Options`, CSP) | Medium | `after_request` hook adding the three headers |
| 6 | User enumeration via timing: unknown email skips bcrypt and answers faster | Low | Compare against a dummy hash when the user doesn't exist |
| 7 | Email format not validated server-side | Low | Minimal regex / length check on register |
| 8 | Flask dev server + SQLite | Info | Workshop scope by design; use a WSGI server + managed DB for real deployment |
