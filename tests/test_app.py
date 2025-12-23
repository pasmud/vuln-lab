import os
import re
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from werkzeug.datastructures import MultiDict
from werkzeug.security import check_password_hash

from vuln_lab import create_app
from vuln_lab.db import BODY_MAX, NOTE_LIMIT, TITLE_MAX, get_db

ALICE_PASSWORD = "synthetic-alice-passphrase"
BOB_PASSWORD = "synthetic-bob-passphrase"
FIXTURE_KEY = "test-only-secret-not-for-local-server-use"
HTTPS = "https://localhost"


class AppFixture(TestCase):
    def setUp(self):
        directory = self.enterContext(TemporaryDirectory())
        self.app = create_app(
            {
                "TESTING": True,
                "DATABASE": Path(directory) / "separate instance" / "notes.sqlite3",
                "SECRET_KEY": FIXTURE_KEY,
                "SESSION_COOKIE_SECURE": True,
            }
        )
        self.runner = self.app.test_cli_runner()
        result = self.runner.invoke(args=["init-db"])
        self.assertEqual(result.exit_code, 0, result.output or repr(result.exception))
        self.add_user("alice", ALICE_PASSWORD)
        self.add_user("bob", BOB_PASSWORD)
        self.client = self.app.test_client()

    def add_user(self, username, password):
        result = self.runner.invoke(args=["add-user", username], input=f"{password}\n{password}\n")
        self.assertEqual(result.exit_code, 0, result.output or repr(result.exception))

    def get(self, path, client=None, **kwargs):
        return (client or self.client).get(path, base_url=HTTPS, **kwargs)

    def post(self, path, data=None, client=None, **kwargs):
        return (client or self.client).post(path, data=data, base_url=HTTPS, **kwargs)

    def token(self, path="/", client=None):
        page = self.get(path, client)
        self.assertEqual(page.status_code, 200)
        markup = page.get_data(as_text=True)
        match = re.search(r'name="csrf_token" value="([A-Za-z0-9_-]+)"', markup)
        self.assertIsNotNone(match, "Expected a CSRF input in the rendered form")
        return match[1]

    def sign_in(self, username="alice", password=ALICE_PASSWORD, client=None):
        token = self.token("/login", client)
        data = {"username": username, "password": password, "csrf_token": token}
        response = self.post("/login", data, client)
        self.assertEqual((response.status_code, response.location), (303, "/"))
        return response

    def create_note(self, title="Garden plans", body="Plant basil.", client=None):
        data = {"title": title, "body": body, "csrf_token": self.token(client=client)}
        response = self.post("/notes", data, client)
        self.assertEqual(response.status_code, 303)
        self.assertRegex(response.location, r"^/notes/[1-9][0-9]*$")
        return response.location


class AccountTests(AppFixture):
    def test_init_is_idempotent_and_password_is_hashed(self):
        self.sign_in()
        path = self.create_note()
        result = self.runner.invoke(args=["init-db"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(self.get(path).status_code, 200)
        with self.app.app_context():
            query = "SELECT password_hash FROM users WHERE username = ?"
            stored = get_db().execute(query, ("alice",)).fetchone()["password_hash"]
        self.assertNotEqual(stored, ALICE_PASSWORD)
        self.assertTrue(stored.startswith("scrypt:"))
        self.assertTrue(check_password_hash(stored, ALICE_PASSWORD))

    def test_cli_rejects_invalid_username_short_password_and_duplicate(self):
        for username, password, message in (
            ("Alice Smith", ALICE_PASSWORD, "lowercase ASCII"),
            ("new_user", "too-short", "12–128 characters"),
            ("alice", "different-synthetic-password", "already exists"),
        ):
            with self.subTest(username=username):
                result = self.runner.invoke(
                    args=["add-user", username], input=f"{password}\n{password}\n"
                )
                self.assertNotEqual(result.exit_code, 0)
                self.assertIn(message, result.output)
        self.sign_in()

    def test_configured_database_is_explicitly_initialized_and_preserves_data(self):
        original = self.app.config["DATABASE"]
        self.sign_in()
        self.create_note("Original database note")

        alternate = original.parent / "alternate store" / "notes #2.sqlite3"
        with patch.dict(os.environ, {"VULN_LAB_DATABASE": str(alternate)}):
            app = create_app({"TESTING": True, "SECRET_KEY": FIXTURE_KEY})
        self.assertFalse(alternate.parent.exists())
        runner = app.test_cli_runner()
        result = runner.invoke(args=["init-db"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertTrue(alternate.is_file())
        result = runner.invoke(args=["add-user", "alice"], input=f"{ALICE_PASSWORD}\n" * 2)
        self.assertEqual(result.exit_code, 0, result.output)
        client = app.test_client()
        self.sign_in(client=client)
        self.assertIn(b"No notes yet.", self.get("/", client).data)
        path = self.create_note("Alternate database note", client=client)

        result = runner.invoke(args=["init-db"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn(b"Alternate database note", self.get(path, client).data)
        self.assertNotIn(b"Alternate database note", self.get("/").data)
        self.assertIn(b"Original database note", self.get("/").data)
        self.client.application = app  # Keep the browser's existing cookie after switching stores.
        response = self.get("/")
        self.assertEqual((response.status_code, response.location), (303, "/login"))

    def test_database_environment_rejects_non_absolute_values(self):
        for value in ("", "notes.sqlite3", "~/notes.sqlite3"):
            with (
                self.subTest(value=value),
                patch.dict(os.environ, {"VULN_LAB_DATABASE": value}),
            ):
                with self.assertRaisesRegex(RuntimeError, "VULN_LAB_DATABASE.*absolute path"):
                    create_app({"SECRET_KEY": FIXTURE_KEY})

    def test_bad_credentials_have_same_response(self):
        token = self.token("/login")
        responses = [
            self.post(
                "/login",
                {"username": username, "password": "wrong-synthetic-password", "csrf_token": token},
            )
            for username in ("alice", "unknown_user")
        ]
        self.assertEqual([response.status_code for response in responses], [401, 401])
        self.assertEqual(responses[0].data, responses[1].data)
        self.assertIn(b"Username or password is incorrect.", responses[0].data)
        self.assertEqual(self.get("/").location, "/login")

    def test_invalid_login_fields_return_bad_request(self):
        token = self.token("/login")
        for username, password in (("Al ICE", ALICE_PASSWORD), ("alice", ""), ("alice", "p" * 129)):
            with self.subTest(username=username, password_length=len(password)):
                response = self.post(
                    "/login", {"username": username, "password": password, "csrf_token": token}
                )
                self.assertEqual(response.status_code, 400)

    def test_anonymous_visitors_cannot_use_note_routes(self):
        for path in ("/", "/notes/1", "/notes/1/edit", "/notes/1/delete"):
            with self.subTest(path=path):
                response = self.get(path)
                self.assertEqual((response.status_code, response.location), (303, "/login"))
        data = {"csrf_token": self.token("/login"), "title": "Draft", "body": "A first line."}
        self.assertEqual(self.post("/notes", data).location, "/login")
        self.assertEqual(self.post("/notes/1/edit", data).location, "/login")
        self.assertEqual(self.post("/notes/1/delete", data).location, "/login")
        self.sign_in()
        self.assertIn(b"No notes yet.", self.get("/").data)

    def test_login_rotates_form_token_and_logout_clears_session(self):
        anonymous = self.token("/login")
        self.sign_in()
        signed_in = self.token()
        self.assertNotEqual(anonymous, signed_in)
        self.assertEqual(self.post("/logout", {"csrf_token": anonymous}).status_code, 400)
        result = self.post("/logout", {"csrf_token": signed_in})
        self.assertEqual((result.status_code, result.location), (303, "/login"))
        self.assertEqual(self.get("/").location, "/login")
        self.assertNotIn(self.token("/login"), (anonymous, signed_in))


class NoteTests(AppFixture):
    def test_plain_text_round_trip_and_html_escaping(self):
        self.sign_in()
        title = "Alice's tea < coffee & cake"
        body = 'Bring "tea" & cake.\r\nTwo cups > one.'
        path = self.create_note(title, body)
        pages = (self.get("/"), self.get(path))
        for page in pages:
            self.assertIn(b"Alice&#39;s tea &lt; coffee &amp; cake", page.data)
            self.assertNotIn(title.encode(), page.data)
        self.assertIn(b"Bring &#34;tea&#34; &amp; cake.\nTwo cups &gt; one.", pages[1].data)
        with self.app.app_context():
            row = get_db().execute("SELECT title, body FROM notes").fetchone()
        self.assertEqual(tuple(row), (title, body.replace("\r\n", "\n")))

    def test_owner_filter_applies_to_list_read_and_delete(self):
        self.sign_in()
        path = self.create_note("Alice's garden list")
        bob = self.app.test_client()
        self.sign_in("bob", BOB_PASSWORD, bob)
        bob_note = self.create_note("Bob's shopping list", client=bob)

        self.assertNotIn(b"garden list", self.get("/", bob).data)
        self.assertNotIn(b"shopping list", self.get("/").data)
        self.assertEqual(self.get(bob_note, bob).status_code, 200)
        foreign = self.get(path, bob)
        missing = self.get("/notes/9999", bob)
        self.assertEqual(foreign.status_code, 404)
        self.assertEqual(foreign.data, missing.data)
        delete, missing_delete = f"{path}/delete", "/notes/9999/delete"
        confirmation = self.get(delete, bob)
        self.assertEqual(confirmation.status_code, 404)
        self.assertEqual(confirmation.data, self.get(missing_delete, bob).data)
        data = {"csrf_token": self.token(client=bob)}
        result = self.post(delete, data, bob)
        self.assertEqual(result.status_code, 404)
        self.assertEqual(result.data, self.post(missing_delete, data, bob).data)
        self.assertEqual(self.get(path).status_code, 200)

    def test_owner_can_delete_and_get_never_deletes(self):
        self.sign_in()
        path = self.create_note("Basil & mint")
        delete = f"{path}/delete"
        self.assertIn(f'href="{delete}"'.encode(), self.get(path).data)
        confirmation = self.get(delete)
        self.assertEqual(confirmation.status_code, 200)
        self.assertIn(b"Basil &amp; mint", confirmation.data)
        self.assertIn(f'href="{path}">Cancel'.encode(), confirmation.data)
        self.assertEqual(self.get(path).status_code, 200)
        data = {"csrf_token": self.token(delete)}
        result = self.post(delete, data)
        self.assertEqual((result.status_code, result.location), (303, "/"))
        self.assertEqual(self.post(delete, data).status_code, 404)
        self.assertEqual(self.get(delete).status_code, 404)
        self.assertEqual(self.get(path).status_code, 404)
        self.assertIn(b"No notes yet.", self.get("/").data)

    def test_invalid_note_fields_do_not_write(self):
        self.sign_in()
        token = self.token()
        for title, body in (
            ("  ", "A line."),
            ("Draft", "\n\t"),
            ("a" * (TITLE_MAX + 1), "A line."),
            ("Draft", "b" * (BODY_MAX + 1)),
            ("Draft", "One\0line"),
        ):
            with self.subTest(title_length=len(title), body_length=len(body)):
                data = {"csrf_token": token, "title": title, "body": body}
                self.assertEqual(self.post("/notes", data).status_code, 400)
        missing_body = {"csrf_token": token, "title": "Draft"}
        duplicate_title = MultiDict(
            [("csrf_token", token), ("title", "Draft"), ("title", "Another"), ("body", "A line.")]
        )
        for data in (missing_body, duplicate_title):
            self.assertEqual(self.post("/notes", data).status_code, 400)
        self.assertIn(b"No notes yet.", self.get("/").data)

    def test_exact_field_limits_allow_unicode(self):
        self.sign_in()
        path = self.create_note("é" * TITLE_MAX, "🌱" * BODY_MAX)
        self.assertIn("🌱" * BODY_MAX, self.get(path).get_data(as_text=True))

    def test_invalid_and_out_of_range_ids_return_not_found(self):
        self.sign_in()
        data = {"csrf_token": self.token()}
        for note_id in ("draft", "0", "01", "-1", str(2**63), "9" * 100):
            with self.subTest(note_id=note_id):
                self.assertEqual(self.get(f"/notes/{note_id}").status_code, 404)
                self.assertEqual(self.post(f"/notes/{note_id}/delete", data).status_code, 404)

    def test_quota_is_per_owner_and_deleting_frees_a_slot(self):
        self.sign_in()
        path = self.create_note()
        with self.app.app_context():
            db = get_db()
            user = db.execute("SELECT id FROM users WHERE username = ?", ("alice",)).fetchone()
            with db:
                db.executemany(
                    "INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)",
                    [(user["id"], "Synthetic seed", "A line.")] * (NOTE_LIMIT - 1),
                )
        self.assertIn(f"{NOTE_LIMIT} of {NOTE_LIMIT} notes".encode(), self.get("/").data)
        data = {"csrf_token": self.token(), "title": "Extra", "body": "A line."}
        self.assertEqual(self.post("/notes", data).status_code, 409)
        bob = self.app.test_client()
        self.sign_in("bob", BOB_PASSWORD, bob)
        self.create_note(client=bob)
        self.assertEqual(self.post(f"{path}/delete", data).status_code, 303)
        self.assertEqual(self.post("/notes", data).status_code, 303)


class SearchTests(AppFixture):
    def test_search_uses_only_owned_titles_in_newest_first_order(self):
        self.sign_in()
        old = self.create_note("Straße plans")
        self.create_note("Garden list", "Meet near the Straße.")
        new = self.create_note("Straße errands")
        bob = self.app.test_client()
        self.sign_in("bob", BOB_PASSWORD, bob)
        self.create_note("Straße shopping", client=bob)

        page = self.get("/", query_string={"q": "  STRASSE  "})
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"3 of 100 notes", page.data)
        self.assertIn(b"2 matching notes", page.data)
        older_link, newer_link = (f'href="{path}"'.encode() for path in (old, new))
        self.assertLess(page.data.index(newer_link), page.data.index(older_link))
        self.assertNotIn(b"Garden list", page.data)
        self.assertNotIn(b"shopping", page.data)

    def test_search_handles_literal_text_empty_terms_and_no_matches(self):
        self.sign_in()
        self.create_note("Save 20%")
        self.create_note("Buy seeds")
        literal = self.get("/", query_string={"q": "%"})
        self.assertIn(b"Save 20%", literal.data)
        self.assertNotIn(b"Buy seeds", literal.data)
        empty = self.get("/", query_string={"q": " "})
        self.assertIn(b"Buy seeds", empty.data)
        self.assertNotIn(b"matching notes", empty.data)
        missing = self.get("/", query_string={"q": "peas"})
        self.assertIn(b"No notes match your search.", missing.data)
        self.assertIn(b'href="/">Clear search', missing.data)

    def test_search_validates_query_bounds(self):
        self.sign_in()
        valid = self.get("/", query_string={"q": "é" * TITLE_MAX})
        self.assertEqual(valid.status_code, 200)
        for query in (
            {"q": "é" * (TITLE_MAX + 1)},
            {"q": "one\0two"},
            MultiDict([("q", "one"), ("q", "two")]),
        ):
            with self.subTest(query=query):
                self.assertEqual(self.get("/", query_string=query).status_code, 400)


class EditTests(AppFixture):
    def test_owner_can_edit_in_place(self):
        self.sign_in()
        path = self.create_note('Basil & "mint"', "\nTea < coffee")
        edit = f"{path}/edit"
        self.assertIn(f'href="{edit}"'.encode(), self.get(path).data)
        page = self.get(edit)
        self.assertEqual(page.status_code, 200)
        self.assertIn(b'value="Basil &amp; &#34;mint&#34;"', page.data)
        self.assertIn(b">\n\nTea &lt; coffee</textarea>", page.data)

        data = {"csrf_token": self.token(edit), "title": "Tea & cake", "body": "One.\r\nTwo."}
        result = self.post(edit, data)
        self.assertEqual((result.status_code, result.location), (303, path))
        self.assertIn(b"Tea &amp; cake", self.get("/").data)
        self.assertNotIn(b"Basil", self.get("/").data)
        self.assertIn(b"One.\nTwo.", self.get(path).data)

    def test_edit_hides_missing_and_other_owners_notes(self):
        self.sign_in()
        path = self.create_note()
        bob = self.app.test_client()
        self.sign_in("bob", BOB_PASSWORD, bob)
        edit, missing = f"{path}/edit", "/notes/9999/edit"
        data = {"csrf_token": self.token(client=bob), "title": "Draft", "body": "A line."}
        for request in (lambda url: self.get(url, bob), lambda url: self.post(url, data, bob)):
            with self.subTest(method=request):
                foreign = request(edit)
                self.assertEqual(foreign.status_code, 404)
                self.assertEqual(foreign.data, request(missing).data)
        self.assertIn(b"Garden plans", self.get(path).data)

    def test_edit_rejects_invalid_fields_and_missing_token_without_changing_note(self):
        self.sign_in()
        path = self.create_note()
        edit = f"{path}/edit"
        self.assertEqual(self.post(edit, {"title": "New", "body": "A line."}).status_code, 400)
        invalid = {"csrf_token": self.token(edit), "title": "New", "body": " "}
        self.assertEqual(self.post(edit, invalid).status_code, 400)
        self.assertIn(b"Garden plans", self.get(path).data)
        self.assertIn(b"Plant basil.", self.get(path).data)


class RequestTests(AppFixture):
    def test_missing_csrf_token_rejects_login_logout_and_delete(self):
        self.assertEqual(
            self.post("/login", {"username": "alice", "password": ALICE_PASSWORD}).status_code, 400
        )
        self.sign_in()
        path = self.create_note()
        for target in ("/logout", f"{path}/delete"):
            with self.subTest(path=target):
                self.assertEqual(self.post(target, {"unused": "value"}).status_code, 400)
        other = self.token("/login", self.app.test_client())
        self.assertEqual(self.post(f"{path}/delete", {"csrf_token": other}).status_code, 400)
        self.assertEqual(self.get(path).status_code, 200)

    def test_invalid_form_tokens_do_not_write(self):
        self.sign_in()
        other_client = self.app.test_client()
        other_token = self.token("/login", other_client)
        fields = [("title", "Draft"), ("body", "A line.")]
        for values in ([], ["wrong-token"], ["café"], [other_token], [self.token()] * 2):
            with self.subTest(value_count=len(values)):
                data = MultiDict([*fields, *(("csrf_token", value) for value in values)])
                self.assertEqual(self.post("/notes", data).status_code, 400)
        self.assertIn(b"No notes yet.", self.get("/").data)

    def test_rejects_unsupported_media_and_oversized_form(self):
        self.sign_in()
        data = {"title": "Draft", "body": "a" * 32768, "csrf_token": self.token()}
        self.assertEqual(self.post("/notes", json=data).status_code, 415)
        self.assertEqual(self.post("/notes", data).status_code, 413)
        self.assertIn(b"No notes yet.", self.get("/").data)

    def test_unrecognized_host_is_rejected(self):
        response = self.get("/login", headers={"Host": "notes.example.test"})
        self.assertEqual(response.status_code, 400)
        self.assertNotIn(b"notes.example.test", response.data)

    def test_loopback_hosts_are_accepted(self):
        for host in ("localhost", "127.0.0.1:5000"):
            with self.subTest(host=host):
                self.assertEqual(self.get("/login", headers={"Host": host}).status_code, 200)

    def test_sensitive_responses_and_errors_have_security_headers(self):
        for response in (self.get("/login"), self.sign_in(), self.get("/notes/9999")):
            with self.subTest(status=response.status_code):
                self.assertEqual(response.headers["Cache-Control"], "no-store")
                self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")
                self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
                csp = response.headers["Content-Security-Policy"]
                directives = ("default-src 'none'", "form-action 'self'", "frame-ancestors 'none'")
                for directive in directives:
                    self.assertIn(directive, csp)

    def test_default_cookie_flags_and_local_http_opt_in(self):
        for flag in ("0", "1"):
            with (
                self.subTest(local_http=flag),
                patch.dict(os.environ, {"VULN_LAB_LOCAL_HTTP": flag}),
            ):
                app = create_app({"TESTING": True, "SECRET_KEY": FIXTURE_KEY})
                cookie = self.get("/login", app.test_client()).headers["Set-Cookie"]
                self.assertEqual("; Secure" in cookie, flag == "0")
                self.assertIn("; HttpOnly", cookie)
                self.assertIn("; SameSite=Lax", cookie)
                self.assertNotIn("; Domain=", cookie)

    def test_startup_rejects_missing_or_short_secret(self):
        for secret in ("", "too-short"):
            with (
                self.subTest(secret=secret),
                patch.dict(os.environ, {"VULN_LAB_SECRET_KEY": secret}),
            ):
                with self.assertRaisesRegex(RuntimeError, "VULN_LAB_SECRET_KEY"):
                    create_app()

    def test_session_lifetime_defaults_to_eight_hours_and_validates_environment(self):
        with patch.dict(os.environ):
            os.environ.pop("VULN_LAB_SESSION_MINUTES", None)
            app = create_app({"SECRET_KEY": FIXTURE_KEY, "DATABASE": self.app.config["DATABASE"]})
        self.assertEqual(app.permanent_session_lifetime, timedelta(hours=8))
        for value in ("", "0", "481", "-1", "1.5", "١", " 30", "9" * 100):
            with (
                self.subTest(value=value),
                patch.dict(os.environ, {"VULN_LAB_SESSION_MINUTES": value}),
            ):
                with self.assertRaisesRegex(RuntimeError, "VULN_LAB_SESSION_MINUTES"):
                    create_app({"SECRET_KEY": FIXTURE_KEY})

    def test_short_session_expires_without_refreshing_on_first_page(self):
        with patch.dict(os.environ, {"VULN_LAB_SESSION_MINUTES": "1"}):
            app = create_app(
                {
                    "TESTING": True,
                    "DATABASE": self.app.config["DATABASE"],
                    "SECRET_KEY": FIXTURE_KEY,
                    "SESSION_COOKIE_SECURE": True,
                }
            )
        client = app.test_client()
        signer_clock = "itsdangerous.TimestampSigner.get_timestamp"
        with patch(signer_clock, return_value=1_800_000_000) as clock:
            login = self.sign_in(client=client)
            self.assertIn("Expires=", login.headers["Set-Cookie"])
            clock.return_value += 59
            page = self.get("/", client)
            self.assertEqual(page.status_code, 200)
            self.assertNotIn("Set-Cookie", page.headers)
            clock.return_value += 2
            expired = self.get("/", client)
            self.assertEqual((expired.status_code, expired.location), (303, "/login"))

    def test_missing_database_is_not_created_by_a_request(self):
        path = self.app.config["DATABASE"]
        path.unlink()
        data = {"username": "alice", "password": ALICE_PASSWORD, "csrf_token": self.token("/login")}
        with self.assertLogs(self.app.logger, "ERROR"):
            response = self.post("/login", data)
        self.assertEqual(response.status_code, 503)
        self.assertNotIn(str(path).encode(), response.data)
        self.assertFalse(path.exists())
