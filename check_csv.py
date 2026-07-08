import sqlite3, os
db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "forensics.db")
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row

img14 = conn.execute("SELECT id, filename FROM DiskImages WHERE id=14").fetchone()
print("Image 14:", dict(img14) if img14 else "NOT FOUND")

img16 = conn.execute("SELECT id, filename FROM DiskImages WHERE id=16").fetchone()
print("Image 16:", dict(img16) if img16 else "NOT FOUND")

count14 = conn.execute("SELECT COUNT(*) AS c FROM DiskFileTree WHERE image_id=14").fetchone()["c"]
print("Files for img 14:", count14)

csv14 = conn.execute("SELECT COUNT(*) AS c FROM DiskFileTree WHERE image_id=14 AND entry_type='file' AND name LIKE '%.csv'").fetchone()["c"]
print("CSVs for img 14:", csv14)

types14 = conn.execute("SELECT entry_type, COUNT(*) AS c FROM DiskFileTree WHERE image_id=14 GROUP BY entry_type").fetchall()
print("Types for img 14:", [dict(r) for r in types14])

csv14names = conn.execute("SELECT name FROM DiskFileTree WHERE image_id=14 AND name LIKE '%.csv'").fetchall()
print("CSV names for img 14:", [r["name"] for r in csv14names])

count16 = conn.execute("SELECT COUNT(*) AS c FROM DiskFileTree WHERE image_id=16").fetchone()["c"]
print("Files for img 16:", count16)

csv16names = conn.execute("SELECT name FROM DiskFileTree WHERE image_id=16 AND name LIKE '%.csv'").fetchall()
print("CSV names for img 16:", [r["name"] for r in csv16names])

conn.close()
