"""RED-phase tests for security fix #6: HTTP security headers (Medium).

Without these headers the browser is free to MIME-sniff responses, let the
page be framed (clickjacking), or leak the full referrer to other sites.
CLAUDE.md §1 explicitly calls for security headers.

Note: a strict Content-Security-Policy is deferred to Phase 3, after the
inline JS/CSS is moved into static files (a strict CSP would break inline
scripts). This suite only pins the headers we can set safely today.
"""

EXPECTED_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
}


def test_security_headers_present_on_every_response(client):
    # A page route and an API route — headers must be on both.
    for path in ("/login", "/tasks"):
        resp = client.get(path)
        for header, value in EXPECTED_HEADERS.items():
            assert resp.headers.get(header) == value, (
                f"{path}: missing/wrong {header} (got {resp.headers.get(header)!r})"
            )
