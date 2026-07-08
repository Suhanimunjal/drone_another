import sys, os, pytsk3

image_path = r"D:\new_WEBSITE\uploads\disk_images\82df0b23-169d-4900-85d5-fc4a884e0f51\converted.raw"
img = pytsk3.Img_Info(image_path)
fs = pytsk3.FS_Info(img, offset=8192*512)
print(f"FS opened, ftype={fs.info.ftype}")

# Try opening directories directly
for dirpath in ["/FlightEncryptLog", "/FlightEncryptLog/RemoteGPS", "/FlightLog", "/FlightLog/Telemetry"]:
    try:
        d = fs.open_dir(path=dirpath)
        count = 0
        for entry in d:
            count += 1
        print(f"{dirpath}: {count} entries (OK)")
    except Exception as e:
        print(f"{dirpath}: FAILED - {e}")

# Try the specific inode from DB
print("\nTrying inode 17415 (RemoteGPS CSV from FlightEncryptLog)...")
try:
    f = fs.open_meta(inode=17415)
    print(f"f = {f}")
    print(f"f.info = {f.info}")
    print(f"f.info.name = {f.info.name}")
    if f.info.name:
        print(f"name = {f.info.name.name}")
except Exception as e:
    print(f"Error: {type(e).__name__}: {e}")

# Try the fs.open_meta with inode 4 (LOST.DIR - known to exist)
print("\nTrying inode 4 (LOST.DIR - known to work)...")
try:
    f = fs.open_meta(inode=4)
    print(f"OK: {f.info.name.name}")
except Exception as e:
    print(f"Error: {type(e).__name__}: {e}")

# Get the root directory entries with inodes
print("\nRoot directory entries:")
root = fs.open_dir(path="/")
for entry in root:
    try:
        name = entry.info.name.name.decode("utf-8", errors="replace")
        inode_v = entry.info.meta.addr
        print(f"  inode={inode_v} name={name}")
    except:
        pass
