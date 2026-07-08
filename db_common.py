"""
db_common.py — Shared DB + auth definitions used by both backend_server and auth_routes.
"""
import os, sqlite3, threading
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "forensics.db")
_db_lock = threading.RLock()

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=60)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

ROLE_SECTIONS = {
    "admin": [
        "overview", "physical-evidence", "disk-image", "cases",
        "ingest", "flight-logs", "timeline", "admin",
    ],
    "forensic_analyst": [
        "overview", "physical-evidence", "disk-image", "cases",
        "ingest", "flight-logs", "timeline",
    ],
    "investigator": [
        "overview",
    ],
}

SECTION_PATHS = {
    "overview", "physical-evidence", "disk-image",
    "cases", "ingest", "flight-logs", "timeline", "admin",
}


class User(UserMixin):
    def __init__(self, id, username, role, password_hash=""):
        self.id = id
        self.username = username
        self.role = role
        self.password_hash = password_hash

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_active(self):
        return True

    def __repr__(self):
        return f"<User {self.username} ({self.role})>"
