import sqlite3, os
db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "forensics.db")
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row

csvs = conn.execute("SELECT name, full_path FROM DiskFileTree WHERE image_id=14 AND name LIKE '%.csv'").fetchall()
print("CSVs:", [dict(r) for r in csvs])

types = conn.execute("SELECT entry_type, COUNT(*) AS c FROM DiskFileTree WHERE image_id=14 GROUP BY entry_type").fetchall()
print("Types:", [dict(r) for r in types])

names = conn.execute("SELECT name FROM DiskFileTree WHERE image_id=14 LIMIT 20").fetchall()
print("Sample names:", [r["name"] for r in names])

# Check if there are files at all with the CSV pattern (case insensitive)
csvs_all = conn.execute("SELECT name FROM DiskFileTree WHERE image_id=14 AND name LIKE '%.CSV'").fetchall()
print("CSV (upper):", [r["name"] for r in csvs_all])

csvs_mixed = conn.execute("SELECT name FROM DiskFileTree WHERE image_id=14 AND (name LIKE '%.csv' OR name LIKE '%.CSV')").fetchall()
print("CSV (either):", [r["name"] for r in csvs_mixed])

conn.close()
