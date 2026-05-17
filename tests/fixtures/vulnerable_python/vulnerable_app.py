# This file is intentionally vulnerable — used as a test fixture for the SAST scanner.
# DO NOT use this code in production.

import os
import pickle
import subprocess
import sqlite3
import yaml
from flask import Flask, request

app = Flask(__name__)

# SEC-001: Hardcoded password
DB_PASSWORD = "admin123"

# SEC-002: Hardcoded API key
API_KEY = "sk-prod-XYZ789abcdefghijklmnop"

# SQLI-002: SQL injection via f-string
def get_user(username):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
    return cursor.fetchone()

# SQLI-002: SQL injection via string formatting
def get_product(product_id):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE id = %s" % product_id)
    return cursor.fetchone()

# CMD-002: Command injection with shell=True
def ping_host(host):
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)
    return result.stdout

# CMD-003: eval with user input
@app.route("/calc")
def calculator():
    expr = request.args.get("expr")
    return str(eval(expr))

# DESER-002: Unsafe pickle deserialization
@app.route("/load")
def load_data():
    raw = request.data
    obj = pickle.loads(raw)
    return str(obj)

# DESER-003: Unsafe yaml.load
def load_config(config_str):
    return yaml.load(config_str)

# PATH-002: Path traversal via open()
@app.route("/file")
def read_file():
    filename = request.args.get("name")
    with open("/var/data/" + filename) as f:
        return f.read()

# PATH-004: File upload with original filename
@app.route("/upload", methods=["POST"])
def upload():
    f = request.files["file"]
    f.save(f"/uploads/{f.filename}")
    return "ok"

# XSS-004: Markup() marks user input as safe HTML
@app.route("/greet", methods=["GET"])
def greet():
    name = request.args.get("name", "")
    return Markup("<h1>Hello " + name + "</h1>")

# XSS-005: render_template_string with user input (also SSTI)
@app.route("/render", methods=["GET"])
def render():
    return render_template_string(request.args.get("t", ""))
