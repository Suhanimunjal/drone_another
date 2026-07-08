import sqlite3, os
db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "forensics.db")
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row

parts = conn.execute("SELECT * FROM DiskPartitions WHERE image_id=14").fetchall()
print("Partitions for img 14:")
for r in parts:
    d = dict(r)
    print(f'  id={d["id"]} start={d["start_sector"]} type={d["type"]} status={d["status"]}')

count_files = conn.execute("SELECT COUNT(*) AS c FROM DiskFileTree WHERE image_id=14").fetchone()["c"]
print(f"Files: {count_files}")

status = conn.execute("SELECT status FROM DiskImages WHERE id=14").fetchone()
print(f"Status: {status['status']}")
conn.close()
