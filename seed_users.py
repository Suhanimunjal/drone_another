"""
seed_users.py — Create initial test accounts. Run ONCE.
Usage: python seed_users.py
"""
import sqlite3, os
from werkzeug.security import generate_password_hash

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "forensics.db")

def seed():
    conn = sqlite3.connect(DB_PATH, timeout=60)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")

    seed_accounts = [
        {"username": "admin",          "password": "ChangeMe_Admin123!",        "role": "admin"},
        {"username": "analyst1",       "password": "ChangeMe_Analyst123!",     "role": "forensic_analyst"},
        {"username": "investigator1",  "password": "ChangeMe_Investigator123!", "role": "investigator"},
    ]

    for acct in seed_accounts:
        existing = conn.execute("SELECT id FROM users WHERE username=?", (acct["username"],)).fetchone()
        if existing:
            print(f"  [skip] {acct['username']} already exists")
            continue
        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (acct["username"], generate_password_hash(acct["password"]), acct["role"]),
        )
        print(f"  [created] {acct['username']} ({acct['role']})")

    conn.commit()
    conn.close()
    print("Done. CHANGE THESE PASSWORDS after first login — they are "
          "placeholder values written in plaintext in this script.")

if __name__ == "__main__":
    seed()
