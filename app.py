"""Auditable Attendance Management System (Flask + SQLite)."""
import csv, hashlib, io, json, os, sqlite3
from datetime import datetime, date
from functools import wraps
from flask import Flask, g, jsonify, request, session, render_template, Response
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-in-production")
BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.environ.get("DB_PATH", os.path.join(BASE, "attendance.db"))
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE") == "1")
SHIFT_START = os.environ.get("SHIFT_START", "09:00")   # check-in after this = late
GRACE_MIN = int(os.environ.get("GRACE_MIN", "10"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, full_name TEXT NOT NULL,
  password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN('admin','manager','employee')),
  department TEXT DEFAULT '', active INTEGER DEFAULT 1, leave_balance INTEGER DEFAULT 14);
CREATE TABLE IF NOT EXISTS attendance(
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, day TEXT NOT NULL,
  check_in TEXT, check_out TEXT, status TEXT, source TEXT DEFAULT 'self',
  active INTEGER DEFAULT 1, supersedes_id INTEGER, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS leaves(
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, start_date TEXT, end_date TEXT,
  reason TEXT, status TEXT DEFAULT 'pending', decided_by INTEGER, decided_at TEXT,
  comment TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS corrections(
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, day TEXT NOT NULL,
  new_check_in TEXT, new_check_out TEXT, reason TEXT, status TEXT DEFAULT 'pending',
  decided_by INTEGER, decided_at TEXT, comment TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_logs(
  id INTEGER PRIMARY KEY, ts TEXT NOT NULL, user_id INTEGER, username TEXT, action TEXT NOT NULL,
  entity TEXT, entity_id INTEGER, old_value TEXT, new_value TEXT, ip TEXT, device TEXT,
  prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
-- Tamper protection: audit logs are append-only, attendance rows can never be deleted
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_logs
  BEGIN SELECT RAISE(ABORT,'audit_logs is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_logs
  BEGIN SELECT RAISE(ABORT,'audit_logs is append-only'); END;
CREATE TRIGGER IF NOT EXISTS att_no_delete BEFORE DELETE ON attendance
  BEGIN SELECT RAISE(ABORT,'attendance rows cannot be deleted'); END;
"""

def now(): return datetime.now().isoformat(timespec="seconds")   # server time only

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB); g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d: d.close()

def init_db():
    c = sqlite3.connect(DB); c.executescript(SCHEMA)
    if not c.execute("SELECT 1 FROM users").fetchone():
        c.execute("INSERT INTO users(username,full_name,password_hash,role) VALUES(?,?,?,?)",
                  ("admin", "System Admin", generate_password_hash(os.environ.get("ADMIN_PASSWORD", "admin123")), "admin"))
    c.commit(); c.close()

# ---------- Audit log with hash chain ----------
def audit(action, entity=None, entity_id=None, old=None, new=None, user=None):
    d = db(); u = user or current_user()
    last = d.execute("SELECT hash FROM audit_logs ORDER BY id DESC LIMIT 1").fetchone()
    prev = last["hash"] if last else "GENESIS"
    rec = dict(ts=now(), user_id=u["id"] if u else None, username=u["username"] if u else None,
               action=action, entity=entity, entity_id=entity_id,
               old_value=json.dumps(old) if old is not None else None,
               new_value=json.dumps(new) if new is not None else None,
               ip=request.remote_addr, device=(request.user_agent.string or "")[:120])
    h = hashlib.sha256((prev + json.dumps(rec, sort_keys=True)).encode()).hexdigest()
    d.execute("""INSERT INTO audit_logs(ts,user_id,username,action,entity,entity_id,old_value,new_value,ip,device,prev_hash,hash)
                 VALUES(:ts,:user_id,:username,:action,:entity,:entity_id,:old_value,:new_value,:ip,:device,:p,:h)""",
              {**rec, "p": prev, "h": h})

def verify_chain():
    prev = "GENESIS"
    for r in db().execute("SELECT * FROM audit_logs ORDER BY id"):
        rec = {k: r[k] for k in ("ts","user_id","username","action","entity","entity_id",
                                 "old_value","new_value","ip","device")}
        ok = r["prev_hash"] == prev and r["hash"] == hashlib.sha256(
            (prev + json.dumps(rec, sort_keys=True)).encode()).hexdigest()
        if not ok: return {"valid": False, "broken_at": r["id"]}
        prev = r["hash"]
    return {"valid": True, "broken_at": None}

# ---------- Auth helpers ----------
def current_user():
    uid = session.get("uid")
    if not uid: return None
    return db().execute("SELECT * FROM users WHERE id=? AND active=1", (uid,)).fetchone()

def login_required(*roles):
    def deco(f):
        @wraps(f)
        def w(*a, **k):
            u = current_user()
            if not u: return jsonify(error="Login required"), 401
            if roles and u["role"] not in roles: return jsonify(error="Not allowed"), 403
            return f(*a, **k)
        return w
    return deco

def rows(q, args=()): return [dict(r) for r in db().execute(q, args)]

def status_for(check_in):
    h, m = map(int, SHIFT_START.split(":"))
    t = datetime.fromisoformat(check_in)
    limit = t.replace(hour=h, minute=m, second=0) .timestamp() + GRACE_MIN * 60
    return "late" if t.timestamp() > limit else "present"

# ---------- Routes ----------
@app.route("/")
def index(): return render_template("index.html")

@app.post("/api/login")
def login():
    j = request.json or {}
    u = db().execute("SELECT * FROM users WHERE username=? AND active=1", (j.get("username",""),)).fetchone()
    if not u or not check_password_hash(u["password_hash"], j.get("password","")):
        audit("LOGIN_FAILED", "user", None, new={"username": j.get("username")}, user=None); db().commit()
        return jsonify(error="Wrong username or password"), 401
    session["uid"] = u["id"]; audit("LOGIN", "user", u["id"], user=u); db().commit()
    return jsonify(id=u["id"], name=u["full_name"], role=u["role"])

@app.post("/api/logout")
def logout():
    if current_user(): audit("LOGOUT", "user", session["uid"]); db().commit()
    session.clear(); return jsonify(ok=True)

@app.get("/api/me")
@login_required()
def me():
    u = current_user()
    return jsonify(id=u["id"], name=u["full_name"], role=u["role"], leave_balance=u["leave_balance"],
                   shift_start=SHIFT_START)

@app.post("/api/attendance/checkin")
@login_required()
def checkin():
    u = current_user(); t = now(); day = t[:10]
    if db().execute("SELECT 1 FROM attendance WHERE user_id=? AND day=? AND active=1", (u["id"], day)).fetchone():
        return jsonify(error="Already checked in today"), 400
    on_leave = db().execute("SELECT 1 FROM leaves WHERE user_id=? AND status='approved' AND ? BETWEEN start_date AND end_date",
                            (u["id"], day)).fetchone()
    cur = db().execute("INSERT INTO attendance(user_id,day,check_in,status,created_at) VALUES(?,?,?,?,?)",
                       (u["id"], day, t, status_for(t), t))
    audit("CHECK_IN", "attendance", cur.lastrowid, new={"check_in": t, "on_approved_leave": bool(on_leave)})
    db().commit(); return jsonify(ok=True, check_in=t)

@app.post("/api/attendance/checkout")
@login_required()
def checkout():
    u = current_user(); t = now()
    r = db().execute("SELECT * FROM attendance WHERE user_id=? AND day=? AND active=1", (u["id"], t[:10])).fetchone()
    if not r: return jsonify(error="No check-in found for today"), 400
    if r["check_out"]: return jsonify(error="Already checked out"), 400
    db().execute("UPDATE attendance SET check_out=? WHERE id=?", (t, r["id"]))
    audit("CHECK_OUT", "attendance", r["id"], old={"check_out": None}, new={"check_out": t})
    db().commit(); return jsonify(ok=True, check_out=t)

@app.get("/api/attendance")
@login_required()
def attendance():
    u = current_user(); month = request.args.get("month") or date.today().strftime("%Y-%m")
    uid = request.args.get("user_id", type=int)
    if u["role"] == "employee": uid = u["id"]
    q = """SELECT a.*, u.full_name FROM attendance a JOIN users u ON u.id=a.user_id
           WHERE a.active=1 AND a.day LIKE ?"""
    args = [month + "%"]
    if uid: q += " AND a.user_id=?"; args.append(uid)
    return jsonify(rows(q + " ORDER BY a.day DESC, u.full_name", args))

@app.post("/api/leaves")
@login_required()
def leave_new():
    u = current_user(); j = request.json or {}
    if not (j.get("start_date") and j.get("end_date")) or j["end_date"] < j["start_date"]:
        return jsonify(error="Enter valid dates"), 400
    cur = db().execute("INSERT INTO leaves(user_id,start_date,end_date,reason,created_at) VALUES(?,?,?,?,?)",
                       (u["id"], j["start_date"], j["end_date"], j.get("reason",""), now()))
    audit("LEAVE_REQUESTED", "leave", cur.lastrowid, new=j); db().commit(); return jsonify(ok=True)

@app.get("/api/leaves")
@login_required()
def leave_list():
    u = current_user()
    q = "SELECT l.*, u.full_name FROM leaves l JOIN users u ON u.id=l.user_id"
    if u["role"] == "employee": return jsonify(rows(q + " WHERE l.user_id=? ORDER BY l.id DESC", (u["id"],)))
    return jsonify(rows(q + " ORDER BY l.id DESC"))

def decide(table, rid, apply_fn=None):
    u = current_user(); j = request.json or {}; d = db()
    r = d.execute(f"SELECT * FROM {table} WHERE id=?", (rid,)).fetchone()
    if not r or r["status"] != "pending": return jsonify(error="Request not found or already decided"), 400
    if r["user_id"] == u["id"]: return jsonify(error="You cannot approve your own request"), 403
    status = "approved" if j.get("approve") else "rejected"
    d.execute(f"UPDATE {table} SET status=?, decided_by=?, decided_at=?, comment=? WHERE id=?",
              (status, u["id"], now(), j.get("comment",""), rid))
    audit(f"{table.upper()}_{status.upper()}", table, rid, old={"status": "pending"},
          new={"status": status, "comment": j.get("comment","")})
    if status == "approved" and apply_fn: apply_fn(r)
    d.commit(); return jsonify(ok=True)

def apply_leave(r):
    days = (date.fromisoformat(r["end_date"]) - date.fromisoformat(r["start_date"])).days + 1
    db().execute("UPDATE users SET leave_balance=MAX(0,leave_balance-?) WHERE id=?", (days, r["user_id"]))

@app.post("/api/leaves/<int:rid>/decide")
@login_required("admin", "manager")
def leave_decide(rid): return decide("leaves", rid, apply_leave)

@app.post("/api/corrections")
@login_required()
def corr_new():
    u = current_user(); j = request.json or {}
    if not (j.get("day") and j.get("reason")): return jsonify(error="Day and reason are required"), 400
    cur = db().execute("""INSERT INTO corrections(user_id,day,new_check_in,new_check_out,reason,created_at)
                          VALUES(?,?,?,?,?,?)""",
                       (u["id"], j["day"], j.get("new_check_in") or None, j.get("new_check_out") or None, j["reason"], now()))
    audit("CORRECTION_REQUESTED", "correction", cur.lastrowid, new=j); db().commit(); return jsonify(ok=True)

@app.get("/api/corrections")
@login_required()
def corr_list():
    u = current_user()
    q = "SELECT c.*, u.full_name FROM corrections c JOIN users u ON u.id=c.user_id"
    if u["role"] == "employee": return jsonify(rows(q + " WHERE c.user_id=? ORDER BY c.id DESC", (u["id"],)))
    return jsonify(rows(q + " ORDER BY c.id DESC"))

def apply_correction(r):
    """Never edit in place: old row is marked inactive, a new versioned row is inserted."""
    d = db(); old = d.execute("SELECT * FROM attendance WHERE user_id=? AND day=? AND active=1", (r["user_id"], r["day"])).fetchone()
    ci = r["new_check_in"] or (old["check_in"] if old else None)
    co = r["new_check_out"] or (old["check_out"] if old else None)
    if old: d.execute("UPDATE attendance SET active=0 WHERE id=?", (old["id"],))
    cur = d.execute("""INSERT INTO attendance(user_id,day,check_in,check_out,status,source,supersedes_id,created_at)
                       VALUES(?,?,?,?,?,?,?,?)""",
                    (r["user_id"], r["day"], ci, co, status_for(ci) if ci else "absent", "correction",
                     old["id"] if old else None, now()))
    audit("ATTENDANCE_CORRECTED", "attendance", cur.lastrowid,
          old=dict(old) if old else None, new={"check_in": ci, "check_out": co, "supersedes": old["id"] if old else None})

@app.post("/api/corrections/<int:rid>/decide")
@login_required("admin", "manager")
def corr_decide(rid): return decide("corrections", rid, apply_correction)

@app.get("/api/users")
@login_required("admin", "manager")
def users_list(): return jsonify(rows("SELECT id,username,full_name,role,department,active,leave_balance FROM users"))

@app.post("/api/users")
@login_required("admin")
def users_new():
    j = request.json or {}
    if not all(j.get(k) for k in ("username", "full_name", "password", "role")): return jsonify(error="All fields required"), 400
    try:
        cur = db().execute("INSERT INTO users(username,full_name,password_hash,role,department) VALUES(?,?,?,?,?)",
                           (j["username"], j["full_name"], generate_password_hash(j["password"]), j["role"], j.get("department","")))
    except sqlite3.IntegrityError: return jsonify(error="Username or role invalid / already exists"), 400
    audit("USER_CREATED", "user", cur.lastrowid, new={k: j[k] for k in ("username", "full_name", "role")})
    db().commit(); return jsonify(ok=True)

@app.get("/api/audit")
@login_required("admin")
def audit_list():
    q, a = "SELECT * FROM audit_logs WHERE 1=1", []
    for f in ("username", "action"):
        if request.args.get(f): q += f" AND {f}=?"; a.append(request.args[f])
    return jsonify(rows(q + " ORDER BY id DESC LIMIT 300", a))

@app.get("/api/audit/verify")
@login_required("admin")
def audit_verify(): return jsonify(verify_chain())

@app.get("/api/report.csv")
@login_required("admin", "manager")
def report():
    month = request.args.get("month") or date.today().strftime("%Y-%m")
    data = rows("""SELECT u.full_name, u.department, a.day, a.check_in, a.check_out, a.status, a.source
                   FROM attendance a JOIN users u ON u.id=a.user_id WHERE a.active=1 AND a.day LIKE ? ORDER BY a.day, u.full_name""",
                (month + "%",))
    out = io.StringIO(); w = csv.writer(out)
    w.writerow(["Name", "Department", "Date", "Check in", "Check out", "Status", "Source"])
    for r in data: w.writerow(r.values())
    audit("REPORT_EXPORTED", "report", None, new={"month": month}); db().commit()
    return Response(out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename=attendance_{month}.csv"})

init_db()
if __name__ == "__main__":
    app.run(debug=True, port=5000)
