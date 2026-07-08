import sys, os, pytsk3

image_path = r"D:\new_WEBSITE\uploads\disk_images\82df0b23-169d-4900-85d5-fc4a884e0f51\converted.raw"
img = pytsk3.Img_Info(image_path)
fs = pytsk3.FS_Info(img, offset=8192*512)
print(f"FS opened, ftype={fs.info.ftype}")

# List all directories recursively to find CSV files
def list_dir(fs, dir_path, depth=0):
    if depth > 3:
        return
    try:
        directory = fs.open_dir(path=dir_path)
        for entry in directory:
            try:
                name = entry.info.name.name.decode("utf-8", errors="replace")
                inode = entry.info.meta.addr
                ftype = entry.info.name.type
                meta = entry.info.meta
                if ftype == pytsk3.TSK_FS_META_TYPE_DIR:
                    sub = os.path.join(dir_path, name).replace("\\", "/")
                    list_dir(fs, sub, depth+1)
                elif name.lower().endswith(".csv"):
                    print(f"CSV: inode={inode} path={dir_path}/{name} size={meta.size}")
            except Exception as e:
                pass
    except Exception as e:
        print(f"Cannot open dir {dir_path}: {e}")

list_dir(fs, "/")
