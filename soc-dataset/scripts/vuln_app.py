import os
import sqlite3
import subprocess

from flask import Flask, request, render_template_string

app = Flask(__name__)
DB_PATH = "/tmp/shop.db"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS products")
    cur.execute("CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price TEXT)")
    cur.executemany(
        "INSERT INTO products (id, name, price) VALUES (?, ?, ?)",
        [(1, "Widget", "9.99"), (2, "Gadget", "19.99"), (3, "Gizmo", "29.99")],
    )
    conn.commit()
    conn.close()


PAGE = """
<!doctype html><html><body>
<h1>Mini Shop</h1>
<form action="/search" method="get">
<input name="q" value="{{q}}"><button>Search</button>
</form>
{% if results is not none %}
<ul>{% for r in results %}<li>{{r}}</li>{% endfor %}</ul>
{% endif %}
{% if error %}<p style="color:red">{{error}}</p>{% endif %}
</body></html>
"""


@app.route("/")
def index():
    return render_template_string(PAGE, q="", results=None, error=None)


@app.route("/search")
def search():
    q = request.args.get("q", "")
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    sql = "SELECT name, price FROM products WHERE name LIKE '%" + q + "%'"
    results, error = [], None
    try:
        cur.execute(sql)
        results = [f"{n}: ${p}" for n, p in cur.fetchall()]
    except sqlite3.Error as e:
        error = str(e)
    conn.close()
    return render_template_string(PAGE, q=q, results=results, error=error)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        return "Invalid credentials", 401
    return "<form method=post><input name=u><input name=p type=password><button>Login</button></form>"


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    try:
        out = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True, timeout=5)
        return "<pre>" + out.stdout + out.stderr + "</pre>"
    except Exception as e:
        return str(e), 500


# --- Reflected XSS: name is reflected unescaped into the page (real, exploitable) ---
@app.route("/profile")
def profile():
    name = request.args.get("name", "Guest")
    return render_template_string("<h1>Welcome, " + name + "!</h1><p>Your profile page.</p>")


# --- SSTI leading to RCE: note is embedded directly into Jinja2 template source, then rendered ---
@app.route("/greet", methods=["GET", "POST"])
def greet():
    note = request.values.get("note", "Have a nice day!")
    template_src = "<div>Message: " + note + "</div>"
    try:
        rendered = render_template_string(template_src)
    except Exception as e:
        return f"Render error: {e}", 400
    return rendered


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000)
