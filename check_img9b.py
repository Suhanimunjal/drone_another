import sqlite3, os
db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "forensics.db")
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row

csvs = conn.execute("SELECT name FROM DiskFileTree WHERE image_id=9 AND name LIKE '%.csv'").fetchall()
print("CSVs for img 9:", [r["name"] for r in csvs])

# All files
files = conn.execute("SELECT name, entry_type FROM DiskFileTree WHERE image_id=9").fetchall()
print("All files for img 9:")
for r in files:
    print(f"  {r['entry_type']}: {r['name']}")

conn.close()
