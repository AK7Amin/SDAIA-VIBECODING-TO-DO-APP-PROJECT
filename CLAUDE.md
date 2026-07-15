# CLAUDE.md — Project Rules
> Derived from the SDAIA "Vibe Coding" workshop (البرمجة التوليدية).
> These rules apply to every task the AI agent performs in this project.

---

## 1. Security Rules (Non-Negotiable)

- **Never hardcode secrets.** No API keys, passwords, or tokens in code. Always use environment variables (`.env`), and make sure `.env` is in `.gitignore`.
- **Always use Prepared Statements / parameterized queries.** Never build SQL by string concatenation (prevents SQL Injection).
- **Hash passwords with bcrypt** (or argon2). Never store passwords as plain text.
- **Add Rate Limiting** on authentication endpoints (e.g., temporary block after 5 failed login attempts).
- **Error messages must be generic.** Never expose stack traces, database structure, or system details to the end user.
- **Validate and sanitize all user input** on every endpoint.
- **All endpoints must have authentication/authorization checks** — verify the session on every request and prevent IDOR (a normal user must never access admin data).
- Do not open unnecessary ports; keep CORS and security headers (CSP, HSTS) correctly configured.
- Do not import outdated, unknown, or unnecessary libraries.

## 2. Test-Driven Development (TDD — Strict Test-First)

- Follow the cycle strictly and in order: **RED → GREEN → REFACTOR**.
  1. **RED:** Tests are written FIRST (by the human or a separate step) and must fail initially.
  2. **GREEN:** Write the minimum code needed to make the existing tests pass.
  3. **REFACTOR:** Clean and improve the code without breaking tests.
- **Never write tests after the code to match its (possibly wrong) behavior.** Tests define the behavior; code follows.
- Include security unit tests (SQL injection attempts, auth bypass, rate-limit checks) and run all tests before every deployment.

## 3. Working Style — Decompose & Checkpoint

- **Break every large task into small, verifiable units** (e.g., database schema → auth system → UI). Never attempt "build the whole app" in one shot.
- **Stop at checkpoints:** build one small piece, verify it works, then move to the next. Don't stack 1000 lines of unreviewed code.
- Before coding a new feature, produce a short plan (Design Prompt) — folder structure, libraries, data flow — then implement (Implementation Prompt).
- For any new project/feature, start from a one-page **PRD**: Overview, Features, UX Flow, Technical Constraints.

## 4. Debugging Rules

- When an error occurs: read the FULL error message / stack trace and use it as the primary evidence. Never guess randomly.
- Identify the **root cause**, explain **why** the error happened, then propose the fix.
- **Isolate** the failing component; don't rewrite unrelated working code.
- When needed, add targeted console logs to trace data flow before "fixing blindly".
- Treat errors as feedback, not failure — iterate: draft → error → fix → next draft.

## 5. Context Management

- Work only with the files relevant to the task (**Signal, not Noise**). Don't pull the whole codebase for a one-file change.
- Reference exact files when editing (the @File pattern) and respect the project's anchor files (router, store/state, config).
- For a big new task, start a fresh conversation/session to avoid context drift.

## 6. Human Review Gates (Trust, but Verify)

The agent may write ~90% of the code, but these areas ALWAYS require line-by-line human review before merge/deploy:
1. **Authentication & payments** (session checks, permission checks, amount validation).
2. **Database operations** — especially DELETE/UPDATE (must have explicit WHERE) and schema migrations.
3. **Infrastructure & secrets** — env files, API keys, CORS/headers, Docker ports.

Flag these sections explicitly in your output and ask for review instead of merging silently.

## 7. Prompt & Output Quality

- Every task the agent receives should be understood through the 5 prompt components: **Persona, Context, Task, Constraints, Tone**. If the request is ambiguous, ask for the missing component instead of guessing.
- Prefer step-by-step reasoning (Chain of Thought) before writing code for non-trivial logic.
- Be concise; don't produce a 500-word essay for a simple task, and never answer "fixed" without showing what changed and why.
- Never blindly trust generated code — the human reads code before running it; write code that is readable and reviewable.

## 8. Mode Awareness

- **Prototype mode ("Make it Work"):** speed and idea validation are allowed to win; minor imperfections tolerated. Never for real users.
- **Production mode ("Make it Last"):** tests + documentation are mandatory, zero tolerance for security flaws. Assume production mode unless told otherwise.

## 9. AI Limitations Acknowledged

- The LLM predicts text; it can hallucinate. Any factual/legal/critical output requires human verification (Human in the Loop).
- The AI is treated as a fast junior developer / force multiplier — the human remains the Architect & Reviewer and owns final judgment.
