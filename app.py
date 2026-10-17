"""
VulnLab - A deliberately vulnerable web application for web exploitation practice.

WARNING: This application is intentionally insecure. Every endpoint here
contains a real, exploitable vulnerability on purpose, for learning and
practicing web exploitation techniques in a controlled, local environment.

Do NOT deploy this on a public server or any network you don't fully
control. Run it only on localhost / inside an isolated container.

Challenges included:
  1. SQL Injection (login bypass + UNION-based data extraction)
  2. Reflected XSS
  3. Stored XSS
  4. OS Command Injection
  5. Insecure Direct Object Reference (IDOR)
  6. Unrestricted File Upload (leading to RCE)
  7. Server-Side Request Forgery (SSRF)
  8. Path Traversal / Local File Inclusion
  9. Broken Authentication (predictable session / weak secret)
 10. Insecure Deserialization (pickle)
"""

import os
import sqlite3
import subprocess
import pickle
import base64
import urllib.request
from flask import Flask, request, render_template, redirect, url_for, session, g, send_from_directory, make_response

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "vulnlab.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
NOTES_DIR = os.path.join(BASE_DIR, "notes")

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(NOTES_DIR, exist_ok=True)

app = Flask(__name__)
# Vuln #9: weak, hardcoded secret key -> predictable/forgeable session cookies
app.secret_key = "vulnlab-secret-123"


# ---------------------------------------------------------------------------
# Database setup
# ---------------------------------------------------------------------------
def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        password TEXT,
        email TEXT,
        is_admin INTEGER DEFAULT 0
    )""")
    cur.execute("""CREATE TABLE comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        author TEXT,
        body TEXT
    )""")
    cur.execute("""CREATE TABLE documents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner TEXT,
        title TEXT,
        content TEXT
    )""")
    cur.executemany("INSERT INTO users (username, password, email, is_admin) VALUES (?, ?, ?, ?)", [
        ("admin", "S3cr3tAdminPass!", "admin@vulnlab.local", 1),
        ("alice", "alicepw123", "alice@vulnlab.local", 0),
        ("bob", "bobpw456", "bob@vulnlab.local", 0),
    ])
    cur.executemany("INSERT INTO comments (author, body) VALUES (?, ?)", [
        ("alice", "Welcome to VulnLab!"),
        ("bob", "This place needs better input validation :)"),
    ])
    cur.executemany("INSERT INTO documents (owner, title, content) VALUES (?, ?, ?)", [
        ("alice", "Alice's private note", "Meet me at the docks at midnight."),
        ("bob", "Bob's private note", "The password to the safe is 1234."),
        ("admin", "Admin notes", "FLAG{idor_and_auth_are_hard}"),
    ])
    conn.commit()
    conn.close()
    with open(os.path.join(NOTES_DIR, "flag.txt"), "w") as f:
        f.write("FLAG{path_traversal_or_lfi_ftw}\n")


# ---------------------------------------------------------------------------
# Home / challenge index
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


# ---------------------------------------------------------------------------
# Challenge 1: SQL Injection - login form built with raw string concatenation
# ---------------------------------------------------------------------------
@app.route("/sqli/login", methods=["GET", "POST"])
def sqli_login():
    error = None
    result = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        db = get_db()
        # VULNERABLE: unsanitized string concatenation into SQL query
        query = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (username, password)
        try:
            cur = db.execute(query)
            row = cur.fetchone()
        except sqlite3.Error as e:
            error = f"DB error: {e}"
            row = None
        if row:
            result = dict(row)
        else:
            error = error or "Invalid credentials"
    return render_template("sqli_login.html", error=error, result=result)


@app.route("/sqli/search")
def sqli_search():
    q = request.args.get("q", "")
    db = get_db()
    results = []
    error = None
    if q:
        # VULNERABLE: UNION-injectable search endpoint
        query = "SELECT id, author, body FROM comments WHERE body LIKE '%%%s%%'" % q
        try:
            results = db.execute(query).fetchall()
        except sqlite3.Error as e:
            error = str(e)
    return render_template("sqli_search.html", q=q, results=results, error=error)


# ---------------------------------------------------------------------------
# Challenge 2: Reflected XSS
# ---------------------------------------------------------------------------
@app.route("/xss/reflected")
def xss_reflected():
    name = request.args.get("name", "")
    # VULNERABLE: user input echoed back without escaping (autoescape bypassed via |safe)
    return render_template("xss_reflected.html", name=name)


# ---------------------------------------------------------------------------
# Challenge 3: Stored XSS
# ---------------------------------------------------------------------------
@app.route("/xss/stored", methods=["GET", "POST"])
def xss_stored():
    db = get_db()
    if request.method == "POST":
        author = request.form.get("author", "anon")
        body = request.form.get("body", "")
        # Stored unescaped; rendered with |safe in the template -> stored XSS
        db.execute("INSERT INTO comments (author, body) VALUES (?, ?)", (author, body))
        db.commit()
    comments = db.execute("SELECT * FROM comments ORDER BY id DESC").fetchall()
    return render_template("xss_stored.html", comments=comments)


# ---------------------------------------------------------------------------
# Challenge 4: OS Command Injection
# ---------------------------------------------------------------------------
@app.route("/cmdi/ping", methods=["GET", "POST"])
def cmdi_ping():
    output = None
    host = ""
    if request.method == "POST":
        host = request.form.get("host", "")
        # VULNERABLE: user input passed straight to the shell
        cmd = "ping -c 1 " + host
        try:
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=5).decode(errors="replace")
        except Exception as e:
            output = str(e)
    return render_template("cmdi_ping.html", output=output, host=host)


# ---------------------------------------------------------------------------
# Challenge 5: IDOR
# ---------------------------------------------------------------------------
@app.route("/idor/login", methods=["GET", "POST"])
def idor_login():
    if request.method == "POST":
        username = request.form.get("username", "")
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("idor_doc", doc_id=user["id"]))
    return render_template("idor_login.html")


@app.route("/idor/doc/<int:doc_id>")
def idor_doc(doc_id):
    if "user_id" not in session:
        return redirect(url_for("idor_login"))
    db = get_db()
    # VULNERABLE: no ownership check - any logged-in user can view any doc id
    doc = db.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
    return render_template("idor_doc.html", doc=doc, doc_id=doc_id)


# ---------------------------------------------------------------------------
# Challenge 6: Unrestricted File Upload
# ---------------------------------------------------------------------------
@app.route("/upload", methods=["GET", "POST"])
def upload():
    message = None
    files_list = os.listdir(UPLOAD_DIR)
    if request.method == "POST":
        f = request.files.get("file")
        if f and f.filename:
            # VULNERABLE: no extension/type/content validation, filename not sanitized
            save_path = os.path.join(UPLOAD_DIR, f.filename)
            f.save(save_path)
            message = f"Uploaded to /uploads/{f.filename}"
            files_list = os.listdir(UPLOAD_DIR)
    return render_template("upload.html", message=message, files=files_list)


@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    # Served statically; if an attacker uploads a .py and this were run under
    # certain configs (or paired with another vuln), it demonstrates upload->RCE chains.
    return send_from_directory(UPLOAD_DIR, filename)


# ---------------------------------------------------------------------------
# Challenge 7: SSRF
# ---------------------------------------------------------------------------
@app.route("/ssrf/fetch", methods=["GET", "POST"])
def ssrf_fetch():
    content = None
    url = ""
    error = None
    if request.method == "POST":
        url = request.form.get("url", "")
        try:
            # VULNERABLE: server fetches any attacker-supplied URL, including
            # internal addresses (e.g. http://127.0.0.1:5000/..., cloud metadata IPs)
            with urllib.request.urlopen(url, timeout=5) as resp:
                content = resp.read(2000).decode(errors="replace")
        except Exception as e:
            error = str(e)
    return render_template("ssrf_fetch.html", content=content, url=url, error=error)


# ---------------------------------------------------------------------------
# Challenge 8: Path Traversal / LFI
# ---------------------------------------------------------------------------
@app.route("/notes/view")
def notes_view():
    filename = request.args.get("file", "flag.txt")
    # VULNERABLE: no sanitization of filename, allows ../ traversal
    path = os.path.join(NOTES_DIR, filename)
    content = None
    error = None
    try:
        with open(path, "r", errors="replace") as fh:
            content = fh.read()
    except Exception as e:
        error = str(e)
    return render_template("notes_view.html", filename=filename, content=content, error=error)


# ---------------------------------------------------------------------------
# Challenge 9: Broken auth - forgeable "remember me" cookie
# ---------------------------------------------------------------------------
@app.route("/auth/remember", methods=["GET", "POST"])
def auth_remember():
    message = None
    if request.method == "POST":
        username = request.form.get("username", "guest")
        resp = make_response(redirect(url_for("auth_remember")))
        # VULNERABLE: trust boundary issue - role embedded in a client-readable,
        # unsigned-looking cookie that the app trusts directly
        resp.set_cookie("remember_user", username)
        resp.set_cookie("role", "user")
        return resp
    remember_user = request.cookies.get("remember_user")
    role = request.cookies.get("role", "user")
    if remember_user:
        message = f"Welcome back, {remember_user}! Role: {role}"
        if role == "admin":
            message += " -- ADMIN PANEL UNLOCKED: FLAG{cookie_trust_is_broken_auth}"
    return render_template("auth_remember.html", message=message)


# ---------------------------------------------------------------------------
# Challenge 10: Insecure Deserialization
# ---------------------------------------------------------------------------
@app.route("/deser/profile", methods=["GET", "POST"])
def deser_profile():
    output = None
    error = None
    if request.method == "POST":
        data_b64 = request.form.get("data", "")
        try:
            raw = base64.b64decode(data_b64)
            # VULNERABLE: unpickling attacker-controlled data -> arbitrary code execution
            obj = pickle.loads(raw)
            output = f"Loaded profile object: {obj!r}"
        except Exception as e:
            error = str(e)
    # Provide a benign example payload (base64 pickle of a dict) for convenience
    example = base64.b64encode(pickle.dumps({"name": "alice", "bio": "hi"})).decode()
    return render_template("deser_profile.html", output=output, error=error, example=example)


if __name__ == "__main__":
    init_db()
    print("VulnLab starting on http://0.0.0.0:5000 (FOR LOCAL/ISOLATED PRACTICE ONLY)")
    app.run(host="0.0.0.0", port=5000, debug=True)
