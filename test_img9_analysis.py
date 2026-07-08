import sys, os, sqlite3
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from disk_image_analyzer import DiskImageAnalyzer

db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "forensics.db")
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row

image_id = 9

# Step 1: Get candidates
candidates = conn.execute(
    "SELECT id, partition_id, name, full_path, inode, extracted_path FROM DiskFileTree "
    "WHERE image_id=? AND entry_type='file' AND name LIKE '%.csv'",
    (image_id,)
).fetchall()
print(f"Candidates: {len(candidates)}")

if not candidates:
    print("No candidates, running auto-analysis...")
    img_row = dict(conn.execute("SELECT * FROM DiskImages WHERE id=?", (image_id,)).fetchone())
    print(f"Image: {img_row['filename']}, path: {img_row['filepath']}")
    print(f"Path exists: {os.path.isfile(img_row['filepath'])}")
    
    if not os.path.isfile(img_row['filepath']):
        print("ERROR: File not found!")
    else:
        image_path = img_row["filepath"]
        print(f"Listing partitions...")
        partitions = DiskImageAnalyzer.list_partitions(image_path)
        print(f"Partitions: {len(partitions)}")
        for p in partitions:
            print(f"  start={p['start_sector']} type={p['type']} fs={p['fs_type']}")
        
        for p in partitions:
            print(f"\nWalking partition at sector {p['start_sector']}...")
            try:
                for batch in DiskImageAnalyzer.walk_filesystem(image_path, p["start_sector"], 0, image_id):
                    print(f"  Got batch of {len(batch)} files")
                print("  Done")
            except Exception as e:
                print(f"  ERROR: {type(e).__name__}: {e}")
                import traceback
                traceback.print_exc()

conn.close()
