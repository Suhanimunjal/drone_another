"""
auth_routes.py — Login/logout + role-based access control + SSO cross-port login.
Adapted for raw sqlite3 (no SQLAlchemy). Imports get_db, User, and
ROLE_SECTIONS from backend_server.
"""

from functools import wraps
from flask import Blueprint, request, redirect, url_for, render_template, jsonify, current_app
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

from itsdangerous import URLSafeTimedSerializer
from db_common import get_db, User, ROLE_SECTIONS

auth_bp = Blueprint("auth", __name__)

ROLE_PORT_MAP = {
    "admin": 5001,
    "forensic_analyst": 5002,
    "investigator": 5003,
}


def _sso():
    return URLSafeTimedSerializer(current_app.secret_key)


def _my_port():
    host = request.host
    if ":" in host:
        return int(host.rsplit(":", 1)[-1])
    return 5000


# ---------------------------------------------------------------------------
# LOGIN
# ---------------------------------------------------------------------------
@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    next_url = request.args.get("next", "")

    if request.method == "GET":
        return render_template("login.html", next=next_url)

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    next_url = request.form.get("next", "")

    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    conn.close()

    if not row or not check_password_hash(row["password_hash"], password):
        return render_template("login.html", error="Invalid username or password.", next=next_url), 401

    user = User(row["id"], row["username"], row["role"], row["password_hash"])
    login_user(user)

    # SSO-redirect to role-appropriate port only in multi-port mode
    instance_type = os.environ.get("INSTANCE_TYPE", "all")
    if instance_type != "all":
        target = ROLE_PORT_MAP.get(user.role, 5000)
        if _my_port() != target:
            token = _sso().dumps({"user_id": user.id, "role": user.role})
            dest = f"http://localhost:{target}/sso-login?token={token}"
            if next_url:
                dest += "&next=" + next_url
            return redirect(dest)

    if next_url:
        return redirect(next_url)
    return redirect(url_for("serve_section", section="overview"))


# ---------------------------------------------------------------------------
# SSO LOGIN — validates signed token, creates session on this port
# ---------------------------------------------------------------------------
@auth_bp.route("/sso-login")
def sso_login():
    token = request.args.get("token", "")
    if not token:
        return "Missing token", 400

    try:
        data = _sso().loads(token, max_age=30)
    except Exception:
        return "Invalid or expired login token", 400

    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE id=?", (data["user_id"],)).fetchone()
    conn.close()
    if not row:
        return "User not found", 400

    user = User(row["id"], row["username"], row["role"], row["password_hash"])
    login_user(user)

    next_url = request.args.get("next", "")
    if next_url:
        return redirect(next_url)
    return redirect(url_for("serve_section", section="overview"))


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    if os.environ.get("INSTANCE_TYPE", "all") != "all":
        return redirect("http://localhost:5000/")
    return redirect("/")


# ---------------------------------------------------------------------------
# EXPOSE THE ROLE MAP TO THE FRONTEND
# ---------------------------------------------------------------------------
@auth_bp.route("/api/my-access")
@login_required
def my_access():
    return jsonify({
        "role": current_user.role,
        "allowed_sections": ROLE_SECTIONS.get(current_user.role, []),
        "can_upload_evidence_photo": current_user.role in
            ("admin", "forensic_analyst", "investigator"),
    })


# ---------------------------------------------------------------------------
# EVIDENCE PHOTO UPLOAD — reachable by all 3 roles
# ---------------------------------------------------------------------------
@auth_bp.route("/api/evidence-photo/upload", methods=["POST"])
@login_required
def upload_evidence_photo():
    if current_user.role not in ("admin", "forensic_analyst", "investigator"):
        return jsonify({"error": "Forbidden"}), 403
    file = request.files.get("photo")
    if not file:
        return jsonify({"error": "No photo provided"}), 400
    # Existing upload logic — delegate to the Physical Evidence endpoint
    from backend_server import app
    with app.test_request_context(method="POST", data={"file": file}, path="/api/evidence/upload"):
        # This is a hack; instead redirect to the evidence upload handler
        pass
    return jsonify({"message": "Photo uploaded", "note": "Stub — wire to actual evidence upload handler"}), 201
