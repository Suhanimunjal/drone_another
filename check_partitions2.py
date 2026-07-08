import sqlite3, os
db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "forensics.db")
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row

parts = conn.execute("SELECT DISTINCT partition_id FROM DiskFileTree WHERE image_id=16 AND name LIKE '%.csv'").fetchall()
print("Distinct partition_ids for CSVs:", [r["partition_id"] for r in parts])

# Check each partition
for pid in [r["partition_id"] for r in parts]:
    p = conn.execute("SELECT * FROM DiskPartitions WHERE id=?", (pid,)).fetchone()
    if p:
        print(f"  Partition id={pid}: start_sector={p['start_sector']}, status={p['status']}")
    else:
        print(f"  Partition id={pid}: NOT FOUND")

# Also check if there are any CSVs with partition_id=None
null_part = conn.execute("SELECT COUNT(*) AS c FROM DiskFileTree WHERE image_id=16 AND name LIKE '%.csv' AND partition_id IS NULL").fetchone()
print(f"CSVs with NULL partition_id: {null_part['c']}")

# Check the flight_encrypt log and flight log group inodes
csvs_fe = conn.execute("SELECT id, name, inode, partition_id FROM DiskFileTree WHERE image_id=16 AND name LIKE '%.csv' AND full_path LIKE '/FlightEncryptLog%' LIMIT 2").fetchall()
print("FlightEncryptLog CSVs:", [dict(r) for r in csvs_fe])
csvs_fl = conn.execute("SELECT id, name, inode, partition_id FROM DiskFileTree WHERE image_id=16 AND name LIKE '%.csv' AND full_path LIKE '/FlightLog%' LIMIT 2").fetchall()
print("FlightLog CSVs:", [dict(r) for r in csvs_fl])

conn.close()
