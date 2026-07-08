import sqlite3, os
db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "forensics.db")
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row

csvs = conn.execute("SELECT id, name, full_path, inode FROM DiskFileTree WHERE image_id=16 AND name LIKE '%.csv'").fetchall()
print("All CSVs with full paths:")
for r in csvs:
    d = dict(r)
    print(f'  id={d["id"]} inode={d["inode"]} path={d["full_path"]} name={d["name"]}')

conn.close()
