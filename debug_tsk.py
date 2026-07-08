import pytsk3, os

raw_path = r"D:\new_WEBSITE\uploads\disk_images\45dc2edf-3f54-4adf-9df7-a67edc7b1f29\converted.raw"
img = pytsk3.Img_Info(raw_path)

# Try Volume_Info
try:
    vol = pytsk3.Volume_Info(img)
    has_vol = True
except Exception as e:
    has_vol = False
    print(f"Volume_Info failed: {e}")

if has_vol:
    for part in vol:
        desc = part.desc.decode("utf-8", errors="replace").strip()
        print(f"  addr={part.addr} start={part.start} len={part.len} desc={desc}")
        # Try opening FS at this offset
        try:
            fs = pytsk3.FS_Info(img, offset=(part.start * 512))
            print(f"    -> FS OK, type={fs.info.ftype}")
        except Exception as e2:
            print(f"    -> FS failed: {e2}")

# Try whole-disk auto-detect
print("\n--- Strategy 2: whole-disk auto-detect ---")
try:
    fs = pytsk3.FS_Info(img)
    print(f"  OK, ftype={fs.info.ftype}")
except Exception as e:
    print(f"  Failed: {e}")

# Try force-probe FAT32
print("\n--- Strategy 3: force-probe FAT32 ---")
try:
    fs = pytsk3.FS_Info(img, offset=0, type=pytsk3.TSK_FS_TYPE_FAT32)
    print(f"  OK, ftype={fs.info.ftype}")
except Exception as e:
    print(f"  Failed: {e}")

# Try force-probe exFAT
print("\n--- Strategy 3: force-probe exFAT ---")
try:
    fs = pytsk3.FS_Info(img, offset=0, type=pytsk3.TSK_FS_TYPE_EXFAT)
    print(f"  OK, ftype={fs.info.ftype}")
except:
    print("  Failed or not supported")
