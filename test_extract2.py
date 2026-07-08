import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from disk_image_analyzer import DiskImageAnalyzer

image_path = r"D:\new_WEBSITE\uploads\disk_images\82df0b23-169d-4900-85d5-fc4a884e0f51\converted.raw"
dest = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_extract_output.csv")

print(f"Extracting inode 17415 from sector 8192 to {dest}...")
try:
    written = DiskImageAnalyzer.extract_file(image_path, 8192, 17415, dest)
    print(f"OK: wrote {written} bytes")
    print(f"File exists: {os.path.isfile(dest)}")
    if os.path.isfile(dest):
        with open(dest, "rb") as f:
            content = f.read()
        print(f"Content ({len(content)} bytes):")
        print(content[:200].decode("utf-8", errors="replace"))
        os.remove(dest)
except Exception as e:
    print(f"FAILED: {type(e).__name__}: {e}")
    import traceback
    traceback.print_exc()

print("\nTrying inode 7175 (sector 8192, /FlightLog/Telemetry/Telemetry_00001.csv)...")
try:
    written = DiskImageAnalyzer.extract_file(image_path, 8192, 7175, dest)
    print(f"OK: wrote {written} bytes")
    if os.path.isfile(dest):
        with open(dest, "rb") as f:
            content = f.read()
        print(f"Content ({len(content)} bytes):")
        print(content[:500].decode("utf-8", errors="replace"))
        os.remove(dest)
except Exception as e:
    print(f"FAILED: {type(e).__name__}: {e}")
    import traceback
    traceback.print_exc()
