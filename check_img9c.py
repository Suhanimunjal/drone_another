import sqlite3, os
db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "forensics.db")
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row

# Check image 9 status
img9 = dict(conn.execute("SELECT * FROM DiskImages WHERE id=9").fetchone())
print(f"Image 9: status={img9['status']}, filepath={img9['filepath']}")
print(f"  Path exists: {os.path.isfile(img9['filepath'])}")

# Check partitions
parts = conn.execute("SELECT id, start_sector, fs_type, status FROM DiskPartitions WHERE image_id=9").fetchall()
print(f"Partitions ({len(parts)}):")
for r in parts:
    print(f"  id={r['id']} start={r['start_sector']} fs={r['fs_type']} status={r['status']}")

# File count
count = conn.execute("SELECT COUNT(*) AS c FROM DiskFileTree WHERE image_id=9").fetchone()
print(f"Files: {count['c']}")

conn.close()
