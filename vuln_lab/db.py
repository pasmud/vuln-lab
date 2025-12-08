import re
import sqlite3
from contextlib import closing
from pathlib import Path

import click
from flask import current_app, g
from flask.cli import with_appcontext
from werkzeug.security import generate_password_hash

USERNAME = re.compile(r"[a-z0-9_\-]{3,32}")
PASSWORD_MIN, PASSWORD_MAX = 12, 128
TITLE_MAX, BODY_MAX, NOTE_LIMIT = 80, 2000, 100


def connect(*, create=False):
    path = Path(current_app.config["DATABASE"]).resolve()
    mode = "rwc" if create else "rw"
    db = sqlite3.connect(f"{path.as_uri()}?mode={mode}", uri=True)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def get_db():
    if "db" not in g:
        g.db = connect()
    return g.db


def close_db(_error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


@click.command("init-db")
@with_appcontext
def init_db():
    """Create missing tables without replacing existing data."""
    path = Path(current_app.config["DATABASE"])
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        schema = Path(__file__).with_name("schema.sql").read_text(encoding="utf-8")
        with closing(connect(create=True)) as db:
            db.executescript(schema)
    except (OSError, sqlite3.Error) as error:
        raise click.ClickException("Could not initialize the database.") from error
    click.echo("Database initialized.")


@click.command("add-user")
@click.argument("username")
@with_appcontext
def add_user(username):
    """Create a local account and prompt for its password."""
    if not USERNAME.fullmatch(username):
        raise click.BadParameter(
            "Use 3–32 lowercase ASCII letters, digits, hyphens or underscores.",
            param_hint="username",
        )
    password = click.prompt("Password", hide_input=True, confirmation_prompt=True)
    if not PASSWORD_MIN <= len(password) <= PASSWORD_MAX:
        raise click.ClickException(f"Use a password of {PASSWORD_MIN}–{PASSWORD_MAX} characters.")
    try:
        db = get_db()
        with db:
            result = db.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?) "
                "ON CONFLICT(username) DO NOTHING",
                (username, generate_password_hash(password)),
            )
    except sqlite3.Error as error:
        raise click.ClickException(
            "Could not write the account. Check the database and init-db."
        ) from error
    if not result.rowcount:
        raise click.ClickException("That username already exists.")
    click.echo(f"Created account: {username}")
