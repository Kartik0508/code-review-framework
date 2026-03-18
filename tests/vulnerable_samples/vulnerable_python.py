"""
VULNERABLE PYTHON SAMPLE — FOR SECURITY SCANNER TESTING ONLY
Each section intentionally contains a common vulnerability.
DO NOT USE THIS CODE IN PRODUCTION.
"""

import hashlib
import os
import pickle
import sqlite3
import subprocess

import requests
from flask import Flask, request, render_template_string

app = Flask(__name__)

# ── VULNERABILITY 1: Hardcoded Credentials (CWE-798, A07) ────────────────────
# BAD: Credentials stored in source code
DATABASE_PASSWORD = "super_secret_db_pass_123"  # noqa: S105
API_KEY = "sk-live-abcdef1234567890abcdef"       # noqa: S105
SECRET_TOKEN = "jwt_secret_do_not_share"         # noqa: S105


# ── VULNERABILITY 2: SQL Injection (CWE-89, A03) ──────────────────────────────
# BAD: User input concatenated directly into SQL
@app.route("/user")
def get_user():
    username = request.args.get("username")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # VULNERABLE: f-string in SQL query
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
    return str(cursor.fetchall())


# ── VULNERABILITY 3: Command Injection (CWE-78, A03) ─────────────────────────
# BAD: User input passed to os.system
@app.route("/ping")
def ping_host():
    host = request.args.get("host", "localhost")
    # VULNERABLE: string concatenation in shell command
    result = os.system("ping -c 1 " + host)
    return f"Exit code: {result}"


# ── VULNERABILITY 4: Path Traversal (CWE-22, A01) ────────────────────────────
# BAD: User-supplied filename used without sanitization
@app.route("/file")
def read_file():
    filename = request.args.get("name")
    # VULNERABLE: user controls the path
    with open("/var/data/" + filename) as f:
        return f.read()


# ── VULNERABILITY 5: Insecure Deserialization (CWE-502, A08) ─────────────────
# BAD: pickle.loads on user-supplied data enables RCE
@app.route("/deserialize", methods=["POST"])
def deserialize():
    data = request.get_data()
    # VULNERABLE: arbitrary code execution via pickle
    obj = pickle.loads(data)
    return str(obj)


# ── VULNERABILITY 6: Weak Password Hashing (CWE-327, A02) ────────────────────
# BAD: MD5 used for password hashing
def hash_password_bad(password: str) -> str:
    # VULNERABLE: MD5 is not suitable for passwords
    return hashlib.md5(password.encode()).hexdigest()


def hash_password_also_bad(password: str) -> str:
    # VULNERABLE: SHA1 is also unsuitable for passwords
    return hashlib.sha1(password.encode()).hexdigest()


# ── VULNERABILITY 7: Server-Side Request Forgery / SSRF (CWE-918, A10) ───────
# BAD: User-controlled URL passed to requests.get
@app.route("/fetch")
def fetch_url():
    url = request.args.get("url")
    # VULNERABLE: attacker can make the server request internal services
    response = requests.get(url, timeout=5)
    return response.text


# ── VULNERABILITY 8: XSS via Template Injection (CWE-79, A03) ────────────────
# BAD: User input rendered directly in template without escaping
@app.route("/greet")
def greet():
    name = request.args.get("name", "World")
    # VULNERABLE: user input in template — XSS possible
    template = f"<html><body><h1>Hello, {name}!</h1></body></html>"
    return render_template_string(template)


# ── VULNERABILITY 9: Debug Mode Enabled (CWE-94, A05) ────────────────────────
# BAD: debug=True exposes an interactive debugger in production
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)  # VULNERABLE


# ── VULNERABILITY 10: Subprocess with shell=True (CWE-78, A03) ───────────────
# BAD: shell=True with user input
def run_report(report_name):
    # VULNERABLE: shell=True allows command injection via report_name
    subprocess.call("generate_report.sh " + report_name, shell=True)


# ── VULNERABILITY 11: Sensitive Data in Logs (CWE-532, A09) ──────────────────
import logging

def authenticate_user(username, password):
    logging.info(f"Login attempt: username={username} password={password}")  # VULNERABLE
    return username == "admin" and password == DATABASE_PASSWORD
