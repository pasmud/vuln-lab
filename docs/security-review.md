# Security review notes

## Boundaries and evidence

The browser provides credentials, note text, and a note ID. The server determines the caller from Flask's signed session. Authorization happens in the application before returning or changing note data. The local operator can create users and read the SQLite file; the app does not isolate data from that operator.

| Control | Review finding | Regression evidence |
| --- | --- | --- |
| SQL parameters | `vuln_lab/views.py` and `vuln_lab/db.py` pass data separately from fixed SQL text. The only SQL script is the checked-in schema used by `init-db`. A transaction surrounds note writes; the quota predicate and insert are a single statement. | Ordinary text with apostrophes round-trips through SQLite. Limits and per-owner quota are exercised, including freeing a slot by deleting a note. |
| Plain-text rendering | `.html` templates use Jinja's default autoescaping. Note text appears in HTML text or a quoted form value, never in inline code or dynamic links. CSS preserves line breaks after the server normalizes line endings. The CSP permits local styles and disallows scripts. | Comparison signs, quotation marks, and ampersands are escaped in HTML while stored text remains intact, including in the prefilled edit form. |
| Ownership | Listing, reading, editing, and deleting all filter on the session's user ID. Creating derives `owner_id` from the same session. A missing and a non-owned note get the same response, including on the read-only delete confirmation page. The database also enforces that each note has an existing owner. | Independent Alice and Bob sessions verify separate lists, the same response for unavailable records, and that only the owner can edit or delete a note. Loading the confirmation page leaves the note intact. |
| Form and request checks | Every routed POST requires a single URL-encoded CSRF token matching the one in the signed session. Login clears the anonymous session, and logout clears the authenticated session. Host checks allow `localhost` and `127.0.0.1`; the app does not trust proxy headers. The request-body cap is distinct from the field limits. | Tests cover absent, incorrect, duplicate, and other-session tokens; format, length, and ID boundaries; unsupported media; oversized forms; and host validation. |
| Credentials and responses | Werkzeug hashes passwords with scrypt. Validly formatted sign-ins use a password check even for unknown accounts and return the same failure wording. Session cookies are host-only, `HttpOnly`, `SameSite=Lax`, and `Secure` by default. Responses set `no-store`, `nosniff`, `no-referrer`, and a restrictive CSP. | Tests check stored hashes, consistent sign-in failures, cookie flags, response headers, and a generic database-unavailable response. |

## Deliberate limits

- Title search checks only the signed-in owner's list (at most 100 titles), never note bodies. Query text can appear in browser history and server access logs.
- The sample runs on local IPv4 loopback. Host validation is not a substitute for binding the server to loopback. This project doesn't include deployment or TLS configuration, rate limiting, multifactor authentication, or account recovery.
- Flask signs session cookies; it does not encrypt them. The app stores only a user ID, form token, and session metadata in the cookie. Sessions have an eight-hour lifetime with no automatic per-request refresh. Signing out clears the browser session but does not centrally revoke a previously issued cookie; changing the signing key invalidates existing sessions.
- SQLite contents are not encrypted, and deleting a note is not secure erasure. Keep the database in a private instance directory and use synthetic data. Existing file permissions are not changed by `init-db`.
- Account administration is limited to initialization and adding users. There are no schema migrations, sharing, or API. Database busy or open failures return `503`; the app is intended for light, local use.
- The tests exercise the application boundary, not a real browser, TLS stack, or production server. Dependencies are constrained to release series with minimum versions; installs are not hash-locked.
