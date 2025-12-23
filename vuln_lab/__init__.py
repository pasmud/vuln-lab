import hmac
import os
import secrets
import sqlite3
from datetime import timedelta
from pathlib import Path

from flask import Flask, abort, current_app, render_template, request, session
from werkzeug.exceptions import BadRequest, HTTPException, SecurityError, ServiceUnavailable

from . import db, views


def configured_session_lifetime():
    value = os.environ.get("VULN_LAB_SESSION_MINUTES", "480")
    minutes = int(value) if len(value) <= 3 and value.isascii() and value.isdecimal() else 0
    if not 1 <= minutes <= 480:
        raise RuntimeError("VULN_LAB_SESSION_MINUTES must be a whole number from 1 to 480.")
    return timedelta(minutes=minutes)


def protect_form():
    if request.method != "POST" or request.endpoint is None:
        return
    if request.mimetype != "application/x-www-form-urlencoded":
        abort(415)
    submitted = request.form.getlist("csrf_token")
    expected = session.get("csrf_token")
    if (
        len(submitted) != 1
        or not expected
        or not submitted[0].isascii()
        or not secrets.compare_digest(expected, submitted[0])
    ):
        abort(400, description="The form could not be verified. Open the page and try again.")


def secure_response(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; style-src 'self'; base-uri 'none'; "
        "form-action 'self'; frame-ancestors 'none'"
    )
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


def http_error(error):
    # Host validation can fail before Flask can build URLs for the error template.
    if isinstance(error, SecurityError):
        return BadRequest().get_response()
    response = error.get_response()
    response.set_data(render_template("error.html", error=error))
    return response


def database_error(error):
    # Avoid exposing paths or database internals to the browser.
    current_app.logger.error("Database operation failed (%s)", type(error).__name__)
    return http_error(ServiceUnavailable("The notes database is unavailable. Try again later."))


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    database = os.environ.get("VULN_LAB_DATABASE")
    app.config.from_mapping(
        DATABASE=Path(app.instance_path) / "notes.sqlite3",
        SECRET_KEY=os.environ.get("VULN_LAB_SECRET_KEY"),
        SESSION_COOKIE_NAME="vuln_lab_session",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("VULN_LAB_LOCAL_HTTP") != "1",
        SESSION_REFRESH_EACH_REQUEST=False,
        TRUSTED_HOSTS=["localhost", "127.0.0.1"],
        MAX_CONTENT_LENGTH=32 * 1024,
    )
    if test_config is not None:
        app.config.update(test_config)
    if test_config is None or "PERMANENT_SESSION_LIFETIME" not in test_config:
        app.config["PERMANENT_SESSION_LIFETIME"] = configured_session_lifetime()
    key = app.config["SECRET_KEY"]
    if not isinstance(key, str) or len(key.encode("utf-8")) < 32:
        raise RuntimeError("Set VULN_LAB_SECRET_KEY to a random value of at least 32 bytes.")
    if database is not None and (test_config is None or "DATABASE" not in test_config):
        path = Path(database)
        if "\0" in database or not path.is_absolute():
            raise RuntimeError("VULN_LAB_DATABASE must be an absolute path to a SQLite file.")
        path = path.resolve()
        app.config["DATABASE"] = path
        # User IDs are local to each database, so don't carry sessions across paths.
        scope = f"vuln-lab database:{path.as_uri()}".encode("ascii")
        app.secret_key = hmac.digest(key.encode("utf-8"), scope, "sha256")

    app.teardown_appcontext(db.close_db)
    app.cli.add_command(db.init_db)
    app.cli.add_command(db.add_user)
    app.before_request(protect_form)
    app.after_request(secure_response)
    app.jinja_env.globals["csrf_token"] = views.csrf_token
    app.register_error_handler(HTTPException, http_error)
    app.register_error_handler(sqlite3.OperationalError, database_error)
    app.register_blueprint(views.bp)
    return app
