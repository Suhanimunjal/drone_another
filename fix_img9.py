import sqlite3, os
db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "forensics.db")
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row

# Check image 9
img9 = dict(conn.execute("SELECT * FROM DiskImages WHERE id=9").fetchone())
print(f"Image 9 current filepath: {img9['filepath']}")
print(f"Exists: {os.path.isfile(img9['filepath'])}")

# Check if there's a raw file at the 45dc... path
raw_path = r"D:\new_WEBSITE\uploads\disk_images\45dc2edf-3f54-4adf-9df7-a67edc7b1f29\converted.raw"
e01_path = r"D:\new_WEBSITE\uploads\disk_images\45dc2edf-3f54-4adf-9df7-a67edc7b1f29\DF028_Gimbal_SD_Card.E01"
print(f"Raw exists: {os.path.isfile(raw_path)}")
print(f"E01 exists: {os.path.isfile(e01_path)}")

# If raw exists, update image 9 to point to it
if os.path.isfile(raw_path):
    conn.execute("UPDATE DiskImages SET filepath=? WHERE id=?", (raw_path, 9))
    conn.commit()
    print("Updated image 9 filepath to existing raw file!")
    
    # Verify
    img9_new = dict(conn.execute("SELECT * FROM DiskImages WHERE id=9").fetchone())
    print(f"New filepath: {img9_new['filepath']}")

conn.close()
