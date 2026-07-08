import sqlite3, os
db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "forensics.db")
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row

# Check CSV file details
csvs = conn.execute("SELECT id, name, inode, alloc_status, size_bytes FROM DiskFileTree WHERE image_id=16 AND name LIKE '%.csv' LIMIT 10").fetchall()
print("CSV details:")
for r in csvs:
    d = dict(r)
    print(f'  id={d["id"]} name={d["name"]} inode={d["inode"]} alloc={d["alloc_status"]} size={d["size_bytes"]}')

# Check if any CSVs are deleted
deleted = conn.execute("SELECT COUNT(*) AS c FROM DiskFileTree WHERE image_id=16 AND name LIKE '%.csv' AND alloc_status != 'allocated'").fetchone()
print(f'\nNon-allocated: {deleted["c"]}')

csvs_none = conn.execute("SELECT COUNT(*) AS c FROM DiskFileTree WHERE image_id=16 AND name LIKE '%.csv' AND alloc_status IS NULL").fetchone()
print(f'Null alloc: {csvs_none["c"]}')

allocated = conn.execute("SELECT COUNT(*) AS c FROM DiskFileTree WHERE image_id=16 AND name LIKE '%.csv' AND alloc_status = 'allocated'").fetchone()
print(f'Allocated: {allocated["c"]}')

conn.close()
