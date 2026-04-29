from datetime import datetime, timedelta, timezone
import sqlite3
import secrets
import re

from flask import Flask, render_template, request, redirect, url_for, session, flash, abort 
from markupsafe import escape
from werkzeug.security import generate_password_hash, check_password_hash

from db import get_db, close_db, init_db

app = Flask(__name__)
app.config["SECRET_KEY"] = secrets.token_hex(32)

app.config["SESSION_COOKIE_HTTPONLY"] = True # http only fix
app.config["SESSION_COOKIE_SECURE"] = True # cookieuri securzate nu accept conexiuni necriptate
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
app.config["PERMANENT_SESSION_LIFETIME"] = 1800 # sesiune 30 de minute

LOGIN_ATTEMPTS = {}
MAX_ATTEMPTS = 5
LOCKOUT_TIME = 300
#rate limiting configurat
@app.cli.command("init-db")
def init_db_command():
    init_db()
    print("Initialized the database.")

@app.teardown_appcontext
def teardown_db(exception):
    close_db(exception)

def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    db = get_db()
    return db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()

def login_required():
    if not session.get("user_id"):
        abort(401)

def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password):
    if len(password) < 8:
        return False, "Parola trebuie să aibă cel puțin 8 caractere"
    if not re.search(r'[A-Z]', password):
        return False, "Parola trebuie să conțină o literă mare"
    if not re.search(r'[a-z]', password):
        return False, "Parola trebuie să conțină o literă mică"
    if not re.search(r'[0-9]', password):
        return False, "Parola trebuie să conțină o cifră"
    return True, ""

def check_rate_limit(ip):
    now = datetime.now().timestamp()
    if ip in LOGIN_ATTEMPTS:
        attempts, last_attempt = LOGIN_ATTEMPTS[ip]
        if now - last_attempt < LOCKOUT_TIME:
            if attempts >= MAX_ATTEMPTS:
                return False
            LOGIN_ATTEMPTS[ip] = (attempts + 1, now)
        else:
            LOGIN_ATTEMPTS[ip] = (1, now)
    else:
        LOGIN_ATTEMPTS[ip] = (1, now)
    return True

@app.get("/")
def home():
    user = current_user()
    if user:
        return redirect(url_for("profile"))
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip()
        password = request.form.get("password") or ""
        confirm_password = request.form.get("confirm_password") or ""

        if not email or not password:
            flash("Email și parolă sunt obligatorii.")
            return render_template("register.html")

        if not validate_email(email):
            flash("Format email invalid.")
            return render_template("register.html")

        if password != confirm_password:
            flash("Parolele nu se potrivesc.")
            return render_template("register.html")

        is_valid, msg = validate_password(password)
        if not is_valid:
            flash(msg)
            return render_template("register.html")

        password_hash = generate_password_hash(password)

        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (email, password_hash) VALUES (?, ?)",
                (email, password_hash),
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash("Email deja înregistrat.")
            return render_template("register.html")
        except Exception as e:
            flash("A apărut o eroare la înregistrare.")
            return render_template("register.html")

        flash("Cont creat cu succes. Te poți conecta acum.")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip()
        password = request.form.get("password") or ""

        client_ip = request.remote_addr
        if not check_rate_limit(client_ip):
            flash("Prea multe încercări de conectare. Încearcă mai târziu.")
            return render_template("login.html"), 429

        if not email or not password:
            flash("Email sau parolă incorectă.")
            return render_template("login.html")

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        #query parametrizat
        if not user or not check_password_hash(user["password_hash"], password):
            flash("Email sau parolă incorectă.")
            return render_template("login.html")

        session.clear()
        session["user_id"] = user["id"]
        session.permanent = True
        #regeneram sesiunea

        flash(f"Conectat ca: {user['email']}")
        return redirect(url_for("profile"))

    return render_template("login.html")

@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip()

        if not email:
            flash("Email-ul este obligatoriu.")
            return render_template("forgot_password.html")

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

        if not user:
            flash("Dacă email-ul există, vei primi un link de resetare.")
            return render_template("forgot_password.html")

        reset_token = secrets.token_urlsafe(32)
        expiration = datetime.now(timezone.utc) + timedelta(minutes=15)

        #token random, cu timp de expirare

        db.execute(
            "UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE id = ?",
            (reset_token, expiration, user["id"])
        )
        db.commit()

        reset_link = url_for("reset_password", token=reset_token, _external=True)
        flash(f"Link resetare: <a href='{reset_link}'>{reset_link}</a> (Valid 15 minute)")
        return render_template("forgot_password.html")

    return render_template("forgot_password.html")

@app.route("/forgot-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    if request.method == "GET":
        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE reset_token = ? AND reset_token_expires > ?",
            (token, datetime.now(timezone.utc))
        ).fetchone()

        if not user:
            flash("Token invalid sau expirat.")
            return redirect(url_for("login"))

        return render_template("reset_password.html", token=token)

    if request.method == "POST":
        new_password = request.form.get("password") or ""
        confirm_password = request.form.get("confirm_password") or ""

        if not new_password or not confirm_password:
            flash("Parolele sunt obligatorii.")
            return render_template("reset_password.html", token=token)

        if new_password != confirm_password:
            flash("Parolele nu se potrivesc.")
            return render_template("reset_password.html", token=token)

        is_valid, msg = validate_password(new_password)
        if not is_valid:
            flash(msg)
            return render_template("reset_password.html", token=token)

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE reset_token = ? AND reset_token_expires > ?",
            (token, datetime.now(timezone.utc))
        ).fetchone()

        if not user:
            flash("Token invalid sau expirat.")
            return redirect(url_for("login"))

        password_hash = generate_password_hash(new_password)

        db.execute(
            "UPDATE users SET password_hash = ?, reset_token = NULL, reset_token_expires = NULL WHERE id = ?",
            (password_hash, user["id"])
        )
        db.commit()

        flash("Parolă resetată cu succes. Te poți conecta acum.")
        return redirect(url_for("login"))

    return redirect(url_for("login"))

@app.route("/profile", methods=["GET", "POST"])
def profile():
    login_required()
    user = current_user()

    if request.method == "POST":
        bio = escape(request.form.get("bio") or "")
        #sanitizam Html pt a preveni xss
        if len(bio) > 500:
            flash("Bio prea lung (max 500 caractere).")
            return redirect(url_for("profile"))

        db = get_db()
        db.execute("UPDATE users SET bio = ? WHERE id = ?", (bio, user["id"]))
        db.commit()
        flash("Bio actualizat.")
        return redirect(url_for("profile"))

    return render_template("profile.html", user=user)

if __name__ == "__main__":
    app.run(debug=False, ssl_context="adhoc")
