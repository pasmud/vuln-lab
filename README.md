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

Pick a different synthetic passphrase of 12–128 characters for each account. Passwords are prompted without echo and stored as hashes. Only `init-db` creates `instance/notes.sqlite3`; running it again preserves existing accounts and notes. If you restart the app with a newly generated secret, sign in again; the database is unchanged.

Open `http://127.0.0.1:5000/`. `VULN_LAB_LOCAL_HTTP=1` is explicitly for this loopback walkthrough: it disables the cookie's `Secure` flag for that process. Leave it unset for secure cookies. Keep the development server bound to `127.0.0.1` with debug off.

### Try it

1. Sign in as `alice`. Create a note titled `Alice's tea < coffee & cake` with the body `Bring two cups & a spoon.` The punctuation displays as ordinary text.
2. Sign out and sign in as `bob`. The list is empty. Create a note titled `Shopping list` and open it from the list.
3. Sign back in as `alice`. Her tea note is still there and Bob's shopping list is not. Open the tea note and select **Delete note** to remove it.

## Interface and errors

| Method and path | Purpose |
| --- | --- |
| `GET /login`, `POST /login` | Show the sign-in form and authenticate a CLI-created account |
| `GET /` | List the signed-in user's notes, newest first |
| `POST /notes` | Create a note for the signed-in user |
| `GET /notes/<id>` | Read an owned note |
| `POST /notes/<id>/delete` | Delete an owned note |
| `POST /logout` | Sign out |

Successful form submissions redirect with `303`. Missing notes and notes owned by another user both return `404`. Invalid fields or unverifiable forms return `400`, incorrect credentials return `401`, and a request body over 32 KiB on a form route returns `413`. The forms use URL-encoded bodies (`415` for unsupported types). Titles and bodies are limited to 80 and 2,000 characters respectively. At 100 notes, delete one before adding another (`409`). If sign-in returns `503`, check that you ran `init-db` from this checkout and that the SQLite file is accessible.

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
