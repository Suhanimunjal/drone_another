import sqlite3, os
db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "forensics.db")
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row

img9 = conn.execute("SELECT * FROM DiskImages WHERE id=9").fetchone()
if img9:
    d = dict(img9)
    print(f"Image 9: filename={d['filename']}, status={d['status']}, filepath={d['filepath']}")
    print(f"  Exists: {os.path.isfile(d['filepath']) if d['filepath'] else 'NO PATH'}")
else:
    print("Image 9 NOT FOUND")
    # List all images
    imgs = conn.execute("SELECT id, filename, status FROM DiskImages ORDER BY id").fetchall()
    for r in imgs:
        print(f"  id={r['id']} filename={r['filename']} status={r['status']}")

# Check files for image 9
count = conn.execute("SELECT COUNT(*) AS c FROM DiskFileTree WHERE image_id=9").fetchone()
print(f"Files in DiskFileTree for img 9: {count['c']}")

conn.close()
