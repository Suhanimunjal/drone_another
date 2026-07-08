import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from disk_image_analyzer import DiskImageAnalyzer

image_path = r"D:\new_WEBSITE\uploads\disk_images\82df0b23-169d-4900-85d5-fc4a884e0f51\converted.raw"

# Try to open the filesystem at sector 8192
import pytsk3
img = pytsk3.Img_Info(image_path)

print("Opening FS at sector 8192...")
fs = pytsk3.FS_Info(img, offset=8192*512)
print(f"FS opened, ftype={fs.info.ftype}")

# Try to open inode 17415 (first CSV)
print("Opening inode 17415...")
try:
    f = fs.open_meta(inode=17415)
    print(f"File opened: {f.info.name.name}")
    print(f"Size: {f.info.meta.size}")
except Exception as e:
    print(f"Failed: {e}")

# List the root directory
print("\nRoot directory listing (first 10):")
root = fs.open_dir(path="/")
for i, entry in enumerate(root):
    if i >= 10:
        break
    try:
        name = entry.info.name.name.decode("utf-8", errors="replace")
        inode = entry.info.meta.addr
        size = entry.info.meta.size
        print(f"  inode={inode} name={name} size={size}")
    except Exception as e:
        print(f"  Error: {e}")
