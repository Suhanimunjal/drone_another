import sys, os, sqlite3
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Test the full di_flight_log_merged flow for image 16
from datetime import datetime, timezone
from disk_image_analyzer import DiskImageAnalyzer

db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "forensics.db")
_DISK_IMG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads", "disk_images")

conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row

image_id = 16

# 1. Get candidates
candidates = [dict(r) for r in conn.execute(
    "SELECT id, partition_id, name, full_path, inode, extracted_path FROM DiskFileTree "
    "WHERE image_id=? AND entry_type='file' AND name LIKE '%.csv'",
    (image_id,)
).fetchall()]
print(f"Found {len(candidates)} CSV candidates")

# 2. Get image row
img_row = dict(conn.execute("SELECT * FROM DiskImages WHERE id=?", (image_id,)).fetchone())

# 3. Resolve path
image_path = img_row["filepath"]
print(f"Image path: {image_path}, exists: {os.path.isfile(image_path)}")

# 4. Extract files
extracted_ids = []
for i, row in enumerate(candidates):
    part_row = conn.execute(
        "SELECT start_sector FROM DiskPartitions WHERE id=?",
        (row["partition_id"],)
    ).fetchone() if row.get("partition_id") else None
    start_sector = part_row["start_sector"] if part_row else 0
    
    safe_name = row["name"].replace("/", "_").replace("\\", "_")
    dest_dir = os.path.join(_DISK_IMG_DIR, str(image_id), "extracted")
    os.makedirs(dest_dir, exist_ok=True)
    dest_path = os.path.join(dest_dir, str(row["id"]) + "_" + safe_name)
    
    print(f"[{i+1}/{len(candidates)}] Extracting {row['name']} (inode={row['inode']})...", end=" ")
    try:
        written = DiskImageAnalyzer.extract_file(image_path, start_sector, row["inode"], dest_path)
        extracted_ids.append(row["id"])
        print(f"OK ({written} bytes)")
    except Exception as e:
        print(f"FAILED: {e}")

print(f"\nExtracted {len(extracted_ids)}/{len(candidates)} files")
conn.close()
