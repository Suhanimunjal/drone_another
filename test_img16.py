import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Simulate what di_flight_log_merged does for image 16
import sqlite3
db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "forensics.db")
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row

image_id = 16

candidates = [dict(r) for r in conn.execute(
    "SELECT id, partition_id, name, full_path, inode, extracted_path FROM DiskFileTree "
    "WHERE image_id=? AND entry_type='file' AND name LIKE '%.csv'",
    (image_id,)
).fetchall()]
print(f"Candidate CSVs: {len(candidates)}")
if candidates:
    for c in candidates[:3]:
        print(f"  id={c['id']} name={c['name']} partition_id={c['partition_id']} inode={c['inode']} extracted_path={c['extracted_path']}")
        has_extracted = c['extracted_path'] and os.path.isfile(c['extracted_path'])
        print(f"  has_extracted={has_extracted}")

# Check partitions
parts = conn.execute("SELECT id, start_sector, status FROM DiskPartitions WHERE image_id=?", (image_id,)).fetchall()
print(f"Partitions for img 16: {[dict(r) for r in parts]}")

# Check image
img = dict(conn.execute("SELECT * FROM DiskImages WHERE id=?", (image_id,)).fetchone())
print(f"Image filepath: {img.get('filepath')}")
print(f"File exists: {os.path.isfile(img['filepath'])}")

conn.close()
