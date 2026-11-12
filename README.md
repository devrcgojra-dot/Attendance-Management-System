# Auditable Attendance Management System

Flask + SQLite attendance system where every action is traceable and tamper-evident.

## Run
```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py        # open http://127.0.0.1:5000
```
Default login: **admin / admin123** (change it immediately; set `SECRET_KEY` env var in production).
Optional env vars: `SHIFT_START` (09:00), `GRACE_MIN` (10), `DB_PATH`.

## Roles
- **Employee:** check in/out, request leave, request attendance corrections.
- **Manager:** all of the above + approve/reject leaves and corrections (not their own), reports.
- **Admin:** everything + user management + audit log viewer and chain verification.

## How it is auditable
1. `audit_logs`: who, what, when, IP, device, old and new values for every action (including failed logins and report exports).
2. **Hash chain**: each log entry hashes the previous one. Any edit or deletion breaks the chain and shows in Admin → Audit log.
3. **Append-only**: SQLite triggers block UPDATE/DELETE on `audit_logs` and DELETE on `attendance`.
4. **Corrections never overwrite**: approved corrections mark the old row inactive and insert a new version (`supersedes_id`).
5. **Server-side time only**, and no self-approval of requests.

## Structure
`app.py` (API + DB + audit), `templates/index.html` (UI), `requirements.txt`.

## Go live (PythonAnywhere, free, SQLite data stays saved)
1. Sign up at pythonanywhere.com, open **Files**, upload this project (or `git clone` it from Bash console).
2. In a **Bash console**: `cd Attendance-Management-System && pip install --user -r requirements.txt`
3. **Web** tab → *Add a new web app* → *Flask* → Python 3.12 (manual config). Set source code to the project folder.
4. In the WSGI file use:
   ```python
   import sys, os
   sys.path.insert(0, "/home/YOURUSER/Attendance-Management-System")
   os.environ["SECRET_KEY"] = "put-a-long-random-string"
   os.environ["ADMIN_PASSWORD"] = "your-strong-password"   # used only when the DB is first created
   os.environ["COOKIE_SECURE"] = "1"
   from app import app as application
   ```
5. Press **Reload**. Your system is live at `https://YOURUSER.pythonanywhere.com`.
Other hosts (Render, Railway) also work with the included `Procfile`, but need a persistent disk for the SQLite file.
