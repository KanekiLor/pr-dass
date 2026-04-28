from datetime import datetime, timezone
import sqlite3

from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash
import hashlib
import base64
from db import get_db, close_db, init_db

app = Flask(__name__)
app.config["SECRET_KEY"] = "dev-only-change-me"


app.config["SESSION_COOKIE_HTTPONLY"] = False
app.config["SESSION_COOKIE_SECURE"] = False
app.config["SESSION_COOKIE_SAMESITE"] = None
app.config["PERMANENT_SESSION_LIFETIME"] = 2592000

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

@app.get("/")
def home():
    user = current_user()
    if user:
        return redirect(url_for("profile"))
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        mail = (request.form.get("mail") or "").strip()
        password = request.form.get("password") or ""

        if not mail or not password:
            flash("Email și parolă sunt obligatorii.")
            return render_template("register.html")

        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (email, password_hash) VALUES (?, ?)",
                (mail, password),
            )
            db.commit()
        except sqlite3.IntegrityError as e:
            # VULNERABIL 4.4: Enumerare utilizatori - dezvăluie dacă email există
            flash(f"Eroare: Email-ul deja utilizat!")
            return render_template("register.html")
        except Exception as e:
            flash(f"Eroare neașteptată: {e}")
            return render_template("register.html")

        flash("Cont creat. Te poți autentifica.")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = (request.form.get("email") or "")
        password = request.form.get("password") or ""

        db = get_db()
        query = f"SELECT * FROM users WHERE email = '{email}' AND password_hash = '{password}'"
        print (f"Executing query: {query}")
        user = db.execute(query).fetchone()

        if not user:
            flash("Utilizator inexistent sau date incorecte.")
            return render_template("login.html")
        
        if user["password_hash"] != password:
            flash("Parolă incorectă.")
            return render_template("login.html")

        # VULNERABIL 4.5: Fără timeout de sesiune, sesiune permanentă cu expirare foarte lungă
        session.clear()
        session["user_id"] = user["id"]
        session.permanent = True  # VULNERABIL: Sesiune permanentă (30 de zile)
        flash(f"Logat ca: {user['email']} (DEMO INSECURE)")
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
            flash("Dacă email-ul există în sistem, vei primi un link de resetare.")
            return render_template("forgot_password.html")

        reset_token = str(user["id"]) 
        
        db.execute(
            "UPDATE users SET reset_token = ? WHERE id = ?",
            (reset_token, user["id"])
        )
        db.commit()
        
        flash(f"Link de resetare trimis la {email}")
        print(f"[VULNERABIL] Token de resetare pentru {email}: {reset_token}")  
        return render_template("forgot_password.html")
    
    return render_template("forgot_password.html")

@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    if request.method == "GET":
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE reset_token = ?", (token,)).fetchone()
        
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
   

        db = get_db()
        
        db.execute(
            "UPDATE users SET password_hash = ?, reset_token = NULL WHERE reset_token = ?",
            (new_password, token)
        )
        db.commit()
        
        flash("Parolă resetată cu succes. Te poți autentifica acum.")
        return redirect(url_for("login"))
    
    return redirect(url_for("login"))

@app.route("/profile", methods=["GET", "POST"])
def profile():
    login_required()
    user = current_user()

    if request.method == "POST":
        bio = request.form.get("bio") or ""
        db = get_db()
        db.execute("UPDATE users SET bio = ? WHERE id = ?", (bio, user["id"]))
        db.commit()
        flash("Bio actualizat.")
        return redirect(url_for("profile"))

    return render_template("profile.html", user=user)


