# Vuln Lab: Private Notes

A small, defensive Flask learning app. Two local accounts can use the same SQLite database while each sees only their own notes. The normal sign-in and note routes demonstrate bound query parameters, Jinja autoescaping, ownership checks, and form and session protections.

## Quickstart

From the repository root in a POSIX shell, using Python 3.11 or newer:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt

umask 077
export VULN_LAB_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
python -m flask --app vuln_lab init-db
python -m flask --app vuln_lab add-user alice
python -m flask --app vuln_lab add-user bob
VULN_LAB_LOCAL_HTTP=1 python -m flask --app vuln_lab run --host 127.0.0.1 --port 5000
```

Pick a different synthetic passphrase of 12–128 characters for each account. Passwords are prompted without echo and stored as hashes. Only `init-db` creates the database; running it again preserves existing accounts and notes. If you restart the app with a newly generated secret, sign in again; the database is unchanged.

Open `http://127.0.0.1:5000/`. `VULN_LAB_LOCAL_HTTP=1` is explicitly for this loopback walkthrough: it disables the cookie's `Secure` flag for that process. Leave it unset for secure cookies. Keep the development server bound to `127.0.0.1` with debug off.

Signed-in sessions last eight hours by default. For shorter sessions, set `VULN_LAB_SESSION_MINUTES` to a whole number from 1 to 480 using ASCII digits without spaces (for example, `30`). Invalid values fail at startup. Browsing does not extend the session; after expiry, sign in again.

### Database location

The default is `instance/notes.sqlite3`. To use a different file, export `VULN_LAB_DATABASE` with an absolute path (for example, `export VULN_LAB_DATABASE="$HOME/.local/share/vuln-lab/notes.sqlite3"`) before running `init-db`, `add-user`, and the app. Use the same value for all three commands. A relative or empty value fails at startup. Changing the path selects a different database; it does not move or copy notes. Keep the file in a private directory. Sessions for an explicitly configured path are scoped to that path; sign in again when switching files.

### Try it

1. Sign in as `alice`. Create a note titled `Alice's tea < coffee & cake` with the body `Bring two cups & a spoon.` The punctuation displays as ordinary text.
2. Sign out and sign in as `bob`. The list is empty. Create a note titled `Shopping list` and open it from the list.
3. Sign back in as `alice`. Her tea note is still there and Bob's shopping list is not. Open the tea note and select **Edit note** to update it, or choose **Delete note** and then **Delete permanently** to remove it. **Cancel** returns to the note without deleting it.

## Interface and errors

| Method and path | Purpose |
| --- | --- |
| `GET /login`, `POST /login` | Show the sign-in form and authenticate a CLI-created account |
| `GET /` | List the signed-in user's notes, newest first, optionally filtered by `q` |
| `POST /notes` | Create a note for the signed-in user |
| `GET /notes/<id>` | Read an owned note |
| `GET /notes/<id>/edit`, `POST /notes/<id>/edit` | Show the edit form and save changes to an owned note |
| `GET /notes/<id>/delete`, `POST /notes/<id>/delete` | Show confirmation and delete an owned note; only the CSRF-protected POST changes data |
| `POST /logout` | Sign out |

Successful form submissions redirect with `303`. Missing notes and notes owned by another user both return `404`. Invalid fields or unverifiable forms return `400`, incorrect credentials return `401`, and a request body over 32 KiB on a form route returns `413`. The forms use URL-encoded bodies (`415` for unsupported types). Titles and bodies are limited to 80 and 2,000 characters respectively, whether creating or editing. At 100 notes, delete one before adding another (`409`); editing is still available and does not change list order. If sign-in returns `503`, check that you ran `init-db` for the same database path and that the SQLite file is accessible.

**Search note titles** matches a literal, case-insensitive substring of your own titles. An omitted or whitespace-only `q` shows the full list. Repeated terms, NUL characters, or terms longer than 80 characters return `400`. The quota display always counts your full list. Search terms appear in the URL and may be kept in browser history or server access logs.

## Verify

```sh
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
python -m ruff check .
python -m ruff format --check .
python -m pip check
```

The suite uses Flask's in-process client, a separate temporary database for each test, and synthetic accounts. No running server or network service is used. After dependencies are installed, the app and all checks run offline. If you already have compatible wheels in `wheelhouse/`, install offline with `python -m pip install --no-index --find-links wheelhouse -r requirements-dev.txt` instead. GitHub Actions is configured to run the checks on pushes and pull requests on Python 3.11 and 3.14.

See [Security review notes](docs/security-review.md) for the controls, regression coverage, and limitations. This is a local learning project, not a production notes service. Use synthetic notes only.

**Commit timeline:** December 2025 author and committer dates are illustrative portfolio dates and are not evidence of activity on those dates.

[MIT license](LICENSE)
