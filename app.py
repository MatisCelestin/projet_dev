from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3, os, time
import bcrypt
from cryptography.fernet import Fernet
from flask_wtf.csrf import CSRFProtect
import pyotp
from forms import TwoFactorForm, LoginForm, RegisterForm
from flask import abort, flash

MAX_ATTEMPTS = 5
BLOCK_DURATION = 300  # 5 minutes
# Lecture de la clé de chiffrement
with open("secret.key", "rb") as key_file:
    key = key_file.read()

fernet = Fernet(key)

# Paramètres admin
ADMIN_PASSWORD = "test"
ADMIN_SESSION_DURATION = 600

# App Flask
app = Flask(__name__)
app.secret_key = 'supersecret'
csrf = CSRFProtect(app)

def is_admin_logged_in():
    return "admin_time" in session and time.time() - session["admin_time"] < 10


def init_db():
    with sqlite3.connect("data.db") as con:
        cur = con.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password BLOB,
            totp_secret TEXT
        )""")
        cur.execute("""
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            site TEXT,
            login TEXT,
            password TEXT
        )""")
        con.commit()

@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    return response


def get_user_id(username):
    with sqlite3.connect("data.db") as con:
        cur = con.cursor()
        cur.execute("SELECT id FROM users WHERE username=?", (username,))
        row = cur.fetchone()
        return row[0] if row else None


@app.route("/", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username, password = form.username.data, form.password.data
        with sqlite3.connect("data.db") as con:
            cur = con.cursor()
            cur.execute("SELECT password FROM users WHERE username=?", (username,))
            row = cur.fetchone()
            if row:
                stored_hash = row[0]
                if bcrypt.checkpw(password.encode(), stored_hash):
                    session["temp_username"] = username
                    return redirect("/2fa")
        return render_template("login.html", form=form, error="Identifiants incorrects.")
    return render_template("login.html", form=form)


@app.route("/2fa", methods=["GET", "POST"])
def two_factor():
    if "temp_username" not in session:
        return redirect("/")

    if request.method == "POST":
        code = request.form["code"]
        with sqlite3.connect("data.db") as con:
            cur = con.cursor()
            cur.execute("SELECT totp_secret FROM users WHERE username = ?", (session["temp_username"],))
            result = cur.fetchone()

        if not result or result[0] is None:
            return render_template("2fa.html", error="Erreur : aucun code 2FA n’est associé à ce compte.")

        secret = result[0]
        totp = pyotp.TOTP(secret)

        if totp.verify(code):
            session["username"] = session.pop("temp_username")
            return redirect("/home")
            session["user_id"] = get_user_id(session["username"])

        else:
            return render_template("2fa.html", error="Code invalide. Réessaie.")

    return render_template("2fa.html")

# ✅ Désactive CSRF uniquement pour cette route
csrf.exempt(two_factor)


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username, password = form.username.data, form.password.data
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        try:
            with sqlite3.connect("data.db") as con:
                cur = con.cursor()
                totp_secret = pyotp.random_base32()
                cur.execute("INSERT INTO users (username, password, totp_secret) VALUES (?, ?, ?)",
                            (username, hashed, totp_secret))
                con.commit()
                session["username"] = username
            return redirect("/show_qr")
        except:
            return render_template("register.html", form=form, error="Nom d'utilisateur déjà pris.")
    return render_template("register.html", form=form)


("admin_login.html")
@app.route("/show_qr")
def show_qr():
    if "username" not in session:
        return redirect("/")

    with sqlite3.connect("data.db") as con:
        cur = con.cursor()
        cur.execute("SELECT totp_secret FROM users WHERE username=?", (session["username"],))
        result = cur.fetchone()

    if not result or not result[0]:
        return "Erreur : Secret TOTP introuvable pour cet utilisateur.", 500

    secret = result[0]
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=session["username"], issuer_name="MonAppFlask")

    import qrcode
    import io
    from base64 import b64encode
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf)
    img_b64 = b64encode(buf.getvalue()).decode()

    return render_template("show_qr.html", img_b64=img_b64, secret=secret)

@app.route("/admin", methods=["GET", "POST"])
def admin():
    if "admin_attempts" not in session:
        session["admin_attempts"] = 0
        session["admin_blocked_until"] = 0

    if time.time() < session["admin_blocked_until"]:
        return render_template("admin_login.html", error="Trop de tentatives. Réessaye plus tard.")

    if request.method == "POST":
        password = request.form["password"]

        if password == ADMIN_PASSWORD:
            session["admin_authenticated"] = True
            session["admin_time"] = time.time()
            session["admin_attempts"] = 0
            return redirect("/admin/dashboard")
        else:
            session["admin_attempts"] += 1
            if session["admin_attempts"] >= 5:
                session["admin_blocked_until"] = time.time() + 60
                session["admin_attempts"] = 0
                return render_template("admin_login.html", error="Trop de tentatives. Réessaye dans 1 minute.")
            return render_template("admin_login.html", error="Mot de passe incorrect.")

    return render_template("admin_login.html")

@app.route("/admin/dashboard")
def admin_dashboard():
    if not session.get("admin_authenticated"):
        return redirect("/admin")

    with sqlite3.connect("data.db") as con:
        cur = con.cursor()
        cur.execute("SELECT id, username FROM users")
        users = cur.fetchall()

    return render_template("admin.html", users=users)

@app.route("/admin_logout")
def admin_logout():
    session.pop("admin_time", None)
    return redirect("/")


@app.route("/admin/delete_user/<int:user_id>")
def delete_user(user_id):
    if not session.get("admin_authenticated"):
        return redirect("/admin")

    with sqlite3.connect("data.db") as con:
        cur = con.cursor()
        # Supprimer les mots de passe liés
        cur.execute("DELETE FROM passwords WHERE user_id=?", (user_id,))
        # Supprimer l'utilisateur
        cur.execute("DELETE FROM users WHERE id=?", (user_id,))
        con.commit()

    return redirect("/admin/dashboard")

@app.route("/home", methods=["GET", "POST"])
def home():
    if "username" not in session:
        return redirect("/")
    uid = get_user_id(session["username"])

    if request.method == "POST":
        site, login_, pwd = request.form["site"], request.form["login"], request.form["password"]
        encrypted_pwd = fernet.encrypt(pwd.encode()).decode()
        with sqlite3.connect("data.db") as con:
            cur = con.cursor()
            cur.execute("INSERT INTO passwords (user_id, site, login, password) VALUES (?, ?, ?, ?)", (uid, site, login_, encrypted_pwd))
            con.commit()

    query = request.args.get("q", "").strip()

    with sqlite3.connect("data.db") as con:
        cur = con.cursor()
        if query:
            cur.execute("""
                SELECT id, site, login, password FROM passwords
                WHERE user_id=? AND (site LIKE ? OR login LIKE ?)
            """, (uid, f"%{query}%", f"%{query}%"))
        else:
            cur.execute("SELECT id, site, login, password FROM passwords WHERE user_id=?", (uid,))
        entries = [
            (id_, site, login_, fernet.decrypt(pwd.encode()).decode())
            for id_, site, login_, pwd in cur.fetchall()
        ]

    return render_template("home.html", entries=entries)


@app.route("/delete/<int:entry_id>")
def delete(entry_id):
    if "username" not in session:
        return redirect("/")
    uid = get_user_id(session["username"])
    with sqlite3.connect("data.db") as con:
        cur = con.cursor()
        cur.execute("DELETE FROM passwords WHERE id=? AND user_id=?", (entry_id, uid))
        con.commit()
    return redirect("/home")


@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect("/")


@app.before_request
def force_https():
    if not request.is_secure:
        url = request.url.replace("http://", "https://", 1)
        return redirect(url, code=301)


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=8080, ssl_context=('cert.pem', 'key.pem'))
