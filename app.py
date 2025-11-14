# app.py
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash, send_file
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, os, csv, io, json, time
from datetime import datetime

# === Config ===
APP_SECRET = os.environ.get("SECRET_KEY", "supersecretkey_change_me")
PORT = int(os.environ.get("PORT", 5000))
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX = 30     # max postbacks per window per IP

app = Flask(__name__)
app.secret_key = APP_SECRET
CORS(app)

DB = "database.db"

# === In-memory rate limiter ===
rate_store = {}  # {ip: [timestamp,...]}

# === Database helpers ===
def get_conn():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    c = conn.cursor()
    # Users
    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        email TEXT,
        password TEXT,
        role TEXT DEFAULT 'team',
        tracking_id TEXT,
        api_token TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )""")
    # Leads
    c.execute("""
    CREATE TABLE IF NOT EXISTS leads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tracking_id TEXT,
        offer_id TEXT,
        payout REAL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        ip TEXT,
        note TEXT
    )""")
    # Blacklist
    c.execute("""
    CREATE TABLE IF NOT EXISTS blacklist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT UNIQUE,
        reason TEXT,
        blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )""")
    # Admin default
    c.execute("SELECT * FROM users WHERE username='admin'")
    if not c.fetchone():
        c.execute("INSERT INTO users (username, email, password, role) VALUES (?,?,?,?)",
                  ('admin','admin@example.com', generate_password_hash('admin123'), 'admin'))
    conn.commit()
    conn.close()

init_db()

# === Context processor for templates ===
@app.context_processor
def inject_user():
    user = None
    if 'username' in session:
        conn = get_conn()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (session['username'],))
        user = c.fetchone()
        conn.close()
    return dict(current_user=lambda: user)

# === Utilities ===
def is_blocked(ip):
    conn = get_conn(); c = conn.cursor()
    c.execute("SELECT * FROM blacklist WHERE ip=?", (ip,))
    r = c.fetchone()
    conn.close()
    return bool(r)

def rate_ok(ip):
    now = time.time()
    arr = rate_store.get(ip, [])
    arr = [t for t in arr if now - t <= RATE_LIMIT_WINDOW]
    if len(arr) >= RATE_LIMIT_MAX:
        rate_store[ip] = arr
        return False
    arr.append(now)
    rate_store[ip] = arr
    return True

# === Auth helpers ===
def login_user(username, role):
    session.clear()
    session['username'] = username
    session['role'] = role

def current_user():
    u = session.get('username')
    if not u: return None
    conn = get_conn(); c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=?", (u,))
    r = c.fetchone(); conn.close()
    return r

# === Routes ===

@app.route("/")
def root():
    if 'username' in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

# --- Authentication ---
@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        tracking_id = request.form.get("tracking_id")
        if not (username and password and tracking_id):
            flash("Missing fields", "danger")
            return redirect(url_for("register"))
        conn = get_conn(); c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, email, password, role, tracking_id) VALUES (?,?,?,?,?)",
                      (username, email, generate_password_hash(password), 'team', tracking_id))
            conn.commit(); conn.close()
            flash("Registered. Please login.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username already exists", "danger")
            conn.close(); return redirect(url_for("register"))
    return render_template("register.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        conn = get_conn(); c = conn.cursor()
        c.execute("SELECT username, password, role FROM users WHERE username=?", (username,))
        r = c.fetchone(); conn.close()
        if not r:
            flash("User not found", "danger"); return redirect(url_for("login"))
        if not r['password']:
            session['username_temp'] = username
            return redirect(url_for("set_password"))
        if check_password_hash(r['password'], password):
            login_user(username, r['role'])
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid credentials", "danger"); return redirect(url_for("login"))
    return render_template("login.html")

@app.route("/set_password", methods=["GET","POST"])
def set_password():
    username = session.get('username_temp')
    if not username:
        flash("Session expired. Login again.", "danger"); return redirect(url_for("login"))
    if request.method == "POST":
        pw = request.form.get("password")
        conn = get_conn(); c = conn.cursor()
        c.execute("UPDATE users SET password=? WHERE username=?", (generate_password_hash(pw), username))
        conn.commit(); conn.close()
        flash("Password set. Please login.", "success")
        return redirect(url_for("login"))
    return render_template("set_password.html")

@app.route("/change_password", methods=["GET","POST"])
def change_password():
    user = current_user()
    if not user: return redirect(url_for("login"))
    if request.method == "POST":
        old = request.form.get("old_password")
        new = request.form.get("new_password")
        if not check_password_hash(user['password'], old):
            flash("Old password incorrect", "danger")
            return redirect(url_for("change_password"))
        conn = get_conn(); c = conn.cursor()
        c.execute("UPDATE users SET password=? WHERE username=?", (generate_password_hash(new), user['username']))
        conn.commit(); conn.close()
        flash("Password changed", "success")
        return redirect(url_for("dashboard"))
    return render_template("change_password.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# --- Dashboard ---
@app.route("/dashboard")
def dashboard():
    user = current_user()
    if not user: return redirect(url_for("login"))
    filter_tracking = request.args.get("tracking_id")
    date_from = request.args.get("from")
    date_to = request.args.get("to")
    conn = get_conn(); c = conn.cursor()
    if user['role'] == 'admin':
        query = "SELECT tracking_id, offer_id, payout, timestamp FROM leads"
        cond, params = [], []
        if filter_tracking: cond.append("tracking_id=?"); params.append(filter_tracking)
        if date_from: cond.append("date(timestamp) >= date(?)"); params.append(date_from)
        if date_to: cond.append("date(timestamp) <= date(?)"); params.append(date_to)
        if cond: query += " WHERE " + " AND ".join(cond)
        query += " ORDER BY id DESC LIMIT 1000"; c.execute(query, tuple(params))
        leads = c.fetchall()
        c.execute("SELECT tracking_id, COUNT(*) as cnt FROM leads GROUP BY tracking_id"); summary = c.fetchall()
    else:
        tid = user['tracking_id']
        query = "SELECT tracking_id, offer_id, payout, timestamp FROM leads WHERE tracking_id=?"
        params = [tid]
        if date_from: query += " AND date(timestamp) >= date(?)"; params.append(date_from)
        if date_to: query += " AND date(timestamp) <= date(?)"; params.append(date_to)
        query += " ORDER BY id DESC LIMIT 1000"; c.execute(query, tuple(params))
        leads = c.fetchall()
        c.execute("SELECT tracking_id, COUNT(*) as cnt FROM leads WHERE tracking_id=? GROUP BY tracking_id",(tid,))
        summary = c.fetchall()
    conn.close()
    chart_labels = [r['tracking_id'] for r in summary]
    chart_data = [r['cnt'] for r in summary]
    return render_template("dashboard.html", leads=leads, chart_labels=json.dumps(chart_labels), chart_data=json.dumps(chart_data), user=user)

# --- Postback ---
@app.route("/postback", methods=["GET","POST"])
def postback():
    ip = request.remote_addr
    if is_blocked(ip): return jsonify({"status":"blocked"}),403
    if not rate_ok(ip): return jsonify({"status":"rate_limited"}),429
    tracking_id = request.values.get("tracking_id") or request.values.get("subid")
    offer_id = request.values.get("offer_id") or request.values.get("offer")
    payout = request.values.get("payout") or request.values.get("amount")
    if not (tracking_id and offer_id and payout): return jsonify({"status":"error","message":"missing parameters"}),400
    try: payout_val = float(payout)
    except: payout_val = 0.0
    conn = get_conn(); c = conn.cursor()
    c.execute("INSERT INTO leads (tracking_id, offer_id, payout, ip) VALUES (?,?,?,?)",
              (tracking_id, offer_id, payout_val, ip))
    conn.commit(); conn.close()
    return jsonify({"status":"ok"})

# --- Admin Users / Blacklist ---
@app.route("/admin/users", methods=["GET","POST"])
def admin_users():
    user = current_user()
    if not user or user['role'] != 'admin': return redirect(url_for("login"))
    conn = get_conn(); c = conn.cursor()
    if request.method == "POST":
        action = request.form.get("action")
        if action=="add":
            username = request.form.get("username"); tracking_id = request.form.get("tracking_id")
            pw = request.form.get("password") or ""; role = request.form.get("role") or "team"; token = request.form.get("api_token") or None
            try:
                c.execute("INSERT INTO users (username,email,password,role,tracking_id,api_token) VALUES (?,?,?,?,?,?)",
                          (username,None,generate_password_hash(pw) if pw else None, role, tracking_id, token))
                conn.commit(); flash("User added","success")
            except Exception as e: flash(str(e),"danger")
        elif action=="block_ip":
            ip = request.form.get("ip"); reason = request.form.get("reason")
            c.execute("INSERT OR IGNORE INTO blacklist (ip, reason) VALUES (?,?)",(ip,reason)); conn.commit(); flash("IP blocked","success")
        elif action=="unblock_ip":
            ip = request.form.get("ip"); c.execute("DELETE FROM blacklist WHERE ip=?",(ip,)); conn.commit(); flash("IP unblocked","success")
    c.execute("SELECT id, username, role, tracking_id, api_token, created_at FROM users ORDER BY id DESC"); users = c.fetchall()
    c.execute("SELECT ip, reason, blocked_at FROM blacklist ORDER BY id DESC"); black = c.fetchall()
    conn.close()
    return render_template("admin_users.html", users=users, blacklist=black)

# --- Admin export CSV ---
@app.route("/admin/export")
def admin_export():
    user = current_user()
    if not user or user['role'] != 'admin': return redirect(url_for("login"))
    conn = get_conn(); c = conn.cursor()
    c.execute("SELECT tracking_id, offer_id, payout, timestamp, ip FROM leads ORDER BY id DESC"); rows = c.fetchall(); conn.close()
    si = io.StringIO(); cw = csv.writer(si)
    cw.writerow(["tracking_id","offer_id","payout","timestamp","ip"])
    for r in rows: cw.writerow([r['tracking_id'],r['offer_id'],r['payout'],r['timestamp'],r['ip']])
    mem = io.BytesIO(); mem.write(si.getvalue().encode("utf-8")); mem.seek(0)
    return send_file(mem, mimetype="text/csv", as_attachment=True, download_name="leads.csv")

# --- API token access ---
@app.route("/api/leads")
def api_leads():
    token = request.args.get("token")
    if not token: return jsonify({"status":"error","message":"token required"}),401
    conn = get_conn(); c = conn.cursor()
    c.execute("SELECT username, tracking_id FROM users WHERE api_token=?", (token,))
    r = c.fetchone()
    if not r: conn.close(); return jsonify({"status":"error","message":"invalid token"}),403
    tracking = r['tracking_id']
    c.execute("SELECT tracking_id, offer_id, payout, timestamp FROM leads WHERE tracking_id=? ORDER BY id DESC LIMIT 1000",(tracking,))
    rows = c.fetchall(); conn.close()
    return jsonify({"status":"ok","leads":[dict(x) for x in rows]})

# --- Simple health check ---
@app.route("/health")
def health():
    return "OK"

# === Run app ===
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=True)
