import re
import secrets
from functools import wraps

from flask import Blueprint, abort, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from .db import BODY_MAX, NOTE_LIMIT, PASSWORD_MAX, TITLE_MAX, USERNAME, get_db

bp = Blueprint("notes", __name__)
_DUMMY_HASH = generate_password_hash(secrets.token_urlsafe(32))
_NOTE_ID = re.compile(r"[1-9][0-9]{0,18}")


def field(name):
    values = request.form.getlist(name)
    if len(values) != 1:
        abort(400, description="Each form field must be supplied exactly once.")
    return values[0]


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        g.user_id = session.get("user_id")
        if g.user_id is None:
            return redirect(url_for("notes.login"), code=303)
        return view(*args, **kwargs)

    return wrapped


@bp.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id") is not None:
        return redirect(url_for("notes.index"), code=303)
    if request.method != "POST":
        return render_template("login.html")

    username, password = field("username"), field("password")
    if not USERNAME.fullmatch(username) or not 1 <= len(password) <= PASSWORD_MAX:
        abort(400, description="Use a valid username and a password of at most 128 characters.")

    query = "SELECT id, password_hash FROM users WHERE username = ?"
    user = get_db().execute(query, (username,)).fetchone()
    # Perform a password check for both known and unknown usernames.
    valid = check_password_hash(user["password_hash"] if user else _DUMMY_HASH, password)
    if not valid or user is None:
        return render_template("login.html", invalid=True), 401

    session.clear()
    session["user_id"] = user["id"]
    session.permanent = True
    return redirect(url_for("notes.index"), code=303)


@bp.post("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("notes.login"), code=303)


@bp.get("/")
@login_required
def index():
    query = "SELECT id, title FROM notes WHERE owner_id = ? ORDER BY id DESC"
    notes = get_db().execute(query, (g.user_id,)).fetchall()
    return render_template(
        "index.html", notes=notes, title_max=TITLE_MAX, body_max=BODY_MAX, note_limit=NOTE_LIMIT
    )


@bp.post("/notes")
@login_required
def create_note():
    title, body = note_fields()
    db = get_db()
    with db:
        inserted = db.execute(
            "INSERT INTO notes (owner_id, title, body) "
            "SELECT ?, ?, ? WHERE (SELECT count(*) FROM notes WHERE owner_id = ?) < ?",
            (g.user_id, title, body, g.user_id, NOTE_LIMIT),
        )
        if not inserted.rowcount:
            abort(409, description=f"Delete a note before adding more than {NOTE_LIMIT} notes.")
    return redirect(url_for("notes.detail", note_id=inserted.lastrowid), code=303)


def valid_note_field(value, limit):
    return len(value) <= limit and bool(value.strip()) and "\0" not in value


def note_fields():
    title, body = field("title"), field("body").replace("\r\n", "\n").replace("\r", "\n")
    if not valid_note_field(title, TITLE_MAX) or not valid_note_field(body, BODY_MAX):
        abort(
            400,
            description=(
                f"Enter a nonblank title (up to {TITLE_MAX} characters) and body "
                f"(up to {BODY_MAX} characters), without NUL characters."
            ),
        )
    return title, body


def checked_note_id(value):
    if not _NOTE_ID.fullmatch(value):
        abort(404)
    note_id = int(value)
    if note_id > 2**63 - 1:
        abort(404)
    return note_id


def owned_note(note_id):
    query = "SELECT id, title, body FROM notes WHERE id = ? AND owner_id = ?"
    note = get_db().execute(query, (note_id, g.user_id)).fetchone()
    if note is None:
        abort(404)
    return note


@bp.get("/notes/<note_id>")
@login_required
def detail(note_id):
    return render_template("detail.html", note=owned_note(checked_note_id(note_id)))


@bp.route("/notes/<note_id>/edit", methods=["GET", "POST"])
@login_required
def edit_note(note_id):
    note_id = checked_note_id(note_id)
    note = owned_note(note_id)
    if request.method != "POST":
        return render_template("edit.html", note=note, title_max=TITLE_MAX, body_max=BODY_MAX)

    title, body = note_fields()
    db = get_db()
    with db:
        updated = db.execute(
            "UPDATE notes SET title = ?, body = ? WHERE id = ? AND owner_id = ?",
            (title, body, note_id, g.user_id),
        )
        if not updated.rowcount:
            abort(404)
    return redirect(url_for("notes.detail", note_id=note_id), code=303)


@bp.get("/notes/<note_id>/delete")
@login_required
def confirm_delete(note_id):
    return render_template("delete.html", note=owned_note(checked_note_id(note_id)))


@bp.post("/notes/<note_id>/delete")
@login_required
def delete_note(note_id):
    db = get_db()
    with db:
        deleted = db.execute(
            "DELETE FROM notes WHERE id = ? AND owner_id = ?",
            (checked_note_id(note_id), g.user_id),
        )
        if not deleted.rowcount:
            abort(404)
    return redirect(url_for("notes.index"), code=303)
