"""
generate_drone_samples.py
Generates realistic drone SD card disk images (.dd zip archives)
for baseline (pre-crash) and post-crash forensic analysis.
"""

import zipfile, os, json, hashlib, shutil
from datetime import datetime, timezone

OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))
BASELINE_DD = os.path.join(OUTPUT_DIR, "drone_baseline.dd")
CRASH_DD = os.path.join(OUTPUT_DIR, "drone_crash.dd")

def make_file_content(path, kind="text"):
    """Generate realistic file content based on path and type."""
    ext = os.path.splitext(path)[1].lower()
    name = os.path.basename(path)

    if ext == ".mp4":
        # Simulate MP4 header + garbage data
        return b'\x00\x00\x00\x1cftypmp42\x00\x00\x00\x00mp42mp41' + os.urandom(512)

    if ext == ".jpg":
        return b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00' + os.urandom(256)

    if ext == ".bin":
        return os.urandom(128)

    if name == "PARAM.CFG":
        return ("# DJI Mavic 3 Pro Parameter Configuration\n"
                "FW_VERSION=v01.04.0602\n"
                "PID_ROLL_P=0.8000\nPID_ROLL_I=0.0400\nPID_ROLL_D=0.0300\n"
                "PID_PITCH_P=0.8000\nPID_PITCH_I=0.0400\nPID_PITCH_D=0.0300\n"
                "PID_YAW_P=1.2000\nPID_YAW_I=0.0500\nPID_YAW_D=0.0100\n"
                "IMU_CALIB_STATUS=PASS\nCOMPASS_CALIB_STATUS=PASS\n"
                "GPS_TYPE=GPS+GLONASS+Galileo\n"
                "RTL_ALT=100\nMAX_ALT=6000\nMAX_RANGE=15000\n"
                "BAT_LOW_VOLTAGE=3.3\nBAT_CRIT_VOLTAGE=3.0\n"
                "CRC32=0xA3F7B92E\n").encode()

    if name == "RSSI_LOG.CSV":
        lines = ["timestamp,channel,rssi_dbm,packet_loss\n"]
        for i in range(200):
            t = i * 5
            rssi = -55 + (i % 30) * 0.5
            loss = 0 if i < 170 else (2 if i > 170 else 4 if i > 175 else 0)
            lines.append(f"T+{t//60:02d}:{t%60:02d},2.4GHz,{rssi:.1f},{loss}\n")
        return "".join(lines).encode()

    if name == "RC_COMMANDS.CSV":
        lines = ["timestamp,roll,pitch,yaw,throttle\n"]
        for i in range(500):
            t = i * 2
            lines.append(f"T+{t//60:02d}:{t%60:02d},{50+i%10-5},{50+i%15-7},{0},{60+i%5}\n")
        return "".join(lines).encode()

    if name == "GPS_ALMANAC.BIN":
        return b'GPS_ALMANAC_V2' + os.urandom(240)

    if name == "CELL_BALANCE.CSV":
        lines = ["cycle,cell1_v,cell2_v,cell3_v,cell4_v,temp_c\n"]
        for i in range(50):
            lines.append(f"{i+1},{4.2-i*0.01:.3f},{4.19-i*0.01:.3f},{4.21-i*0.01:.3f},{4.18-i*0.01:.3f},{28+i%5}\n")
        return "".join(lines).encode()

    if name == "SETTINGS.XML":
        return ('<?xml version="1.0"?>\n<drone_settings>\n'
                '  <video_resolution>3840x2160</video_resolution>\n'
                '  <video_fps>30</video_fps>\n'
                '  <photo_format>JPEG</photo_format>\n'
                '  <white_balance>AUTO</white_balance>\n'
                '  <iso_range>100-6400</iso_range>\n'
                '  <ae_mode>PROGRAM</ae_mode>\n'
                '</drone_settings>\n').encode()

    if name == "LENS_PROFILE.DAT":
        return b'LENS_PROFILE_HASSELBLAD_LF4_3' + os.urandom(32)

    if name == "CALIBRATION.DAT":
        return b'CALIB_PASS_2026-06-22_IMU1_IMU2_COMPASS' + os.urandom(64)

    if name == "FLY" in name:
        # Simulated flight .DAT log
        seq = name.split(".")[0].replace("FLY", "")
        return (f"FLIGHT_LOG v2\nDrone: DJI Mavic 3 Pro\n"
                f"Session: 2026-06-22 Flight #{seq}\n"
                f"ARM_TIME=T+00:00\nLAUNCH_TIME=T+00:12\n"
                f"WP_REACHED={5*int(seq or 1)}\n"
                f"GPS_FIXES=124\nIMU_SAMPLES=6000\n"
                f"BAT_MIN=3.45V\nMAX_ALT=80m\n"
                f"FLIGHT_DURATION={8+int(seq or 1)*2}min\n"
                + "DATA:" + "A" * 512 + "\n").encode()

    if ext in (".dat", ".bin", ".log"):
        return (f"ARTIFACT: {path}\nTIMESTAMP: 2026-06-22\n"
                + "".join(f"{i:04X}: {os.urandom(8).hex()}\n" for i in range(32))).encode()

    return f"Sample file: {path}\nGenerated: {datetime.now()}\n".encode()


def get_baseline_files():
    """Return list of (path, content) for the baseline (healthy) disk image."""
    files = []

    # DCIM - Camera footage
    for i in range(1, 19):
        files.append((f"DCIM/100MEDIA/DJI_{i:04d}.MP4", make_file_content(f"DJI_{i:04d}.MP4")))
        files.append((f"DCIM/100MEDIA/DJI_{i:04d}.JPG", make_file_content(f"DJI_{i:04d}.JPG")))

    # MISC - Flight logs and config
    for i in range(1, 46):
        files.append((f"MISC/FLY{i:03d}.DAT", make_file_content(f"FLY{i:03d}.DAT")))
    files.append(("MISC/PARAM.CFG", make_file_content("PARAM.CFG")))
    files.append(("MISC/CALIBRATION.DAT", make_file_content("CALIBRATION.DAT")))

    # LOG - Binary flight logs
    for i in range(1, 44):
        files.append((f"LOG/FLY{i:03d}.BIN", make_file_content(f"FLY{i:03d}.BIN")))

    # RADIO
    files.append(("RADIO/RSSI_LOG.CSV", make_file_content("RSSI_LOG.CSV")))
    files.append(("RADIO/RC_COMMANDS.CSV", make_file_content("RC_COMMANDS.CSV")))

    # SYS
    files.append(("SYS/GPS_ALMANAC.BIN", make_file_content("GPS_ALMANAC.BIN")))

    # CAM
    files.append(("CAM/SETTINGS.XML", make_file_content("SETTINGS.XML")))
    files.append(("CAM/LENS_PROFILE.DAT", make_file_content("LENS_PROFILE.DAT")))

    # BAT
    files.append(("BAT/CELL_BALANCE.CSV", make_file_content("CELL_BALANCE.CSV")))

    return files


def get_crash_files():
    """
    Return list of (path, content, status) for the post-crash disk image.
    Status: 'unchanged', 'modified', 'added', 'removed', 'corrupted'
    """
    files = []

    # DCIM - Some videos missing, one corrupted, some unchanged
    for i in range(1, 19):
        if i in (14, 15, 17):
            continue  # removed
        if i == 16:
            files.append(("DCIM/100MEDIA/DJI_0016.MP4", os.urandom(128), "corrupted"))
        elif i == 18:
            files.append(("DCIM/100MEDIA/DJI_0018.MP4", make_file_content(f"DJI_{i:04d}.MP4"), "unchanged"))
        else:
            files.append((f"DCIM/100MEDIA/DJI_{i:04d}.MP4", make_file_content(f"DJI_{i:04d}.MP4"), "unchanged"))

    # MISC - Some DAT files missing, PARAM.CFG modified
    for i in range(1, 46):
        if i in (44, 45):
            continue  # removed
        files.append((f"MISC/FLY{i:03d}.DAT", make_file_content(f"FLY{i:03d}.DAT"), "unchanged"))

    # Modified PARAM.CFG with CRC mismatch
    param_cfg = ("# DJI Mavic 3 Pro Parameter Configuration (POST-CRASH RECOVERY)\n"
                 "FW_VERSION=v01.04.0602\n"
                 "PID_ROLL_P=0.8000\nPID_ROLL_I=0.0400\nPID_ROLL_D=0.0300\n"
                 "PID_PITCH_P=0.8000\nPID_PITCH_I=0.0400\nPID_PITCH_D=0.0300\n"
                 "PID_YAW_P=1.2000\nPID_YAW_I=0.0500\nPID_YAW_D=0.0100\n"
                 "IMU_CALIB_STATUS=FAIL\nCOMPASS_CALIB_STATUS=PASS\n"
                 "GPS_TYPE=GPS+GLONASS+Galileo\n"
                 "RTL_ALT=100\nMAX_ALT=6000\nMAX_RANGE=15000\n"
                 "BAT_LOW_VOLTAGE=3.3\nBAT_CRIT_VOLTAGE=3.0\n"
                 "CRC32=0xDEADBEEF\n").encode()
    files.append(("MISC/PARAM.CFG", param_cfg, "modified"))
    files.append(("MISC/CALIBRATION.DAT", make_file_content("CALIBRATION.DAT"), "unchanged"))

    # LOG - Files missing, crash dump added
    for i in range(1, 44):
        if i == 45:
            continue  # removed
        files.append((f"LOG/FLY{i:03d}.BIN", make_file_content(f"FLY{i:03d}.BIN"), "unchanged"))

    # Crash artifacts
    crash_dump = ("CRASH_DUMP v1.0\n"
                  "TIMESTAMP: 2026-06-22T14:32:47Z\n"
                  "DRONE_ID: CIV-DJI-MAV3P\n"
                  "LAST_ALT: 63.2m\nLAST_VS: -14.2 m/s\n"
                  "LAST_POS: 28.6147,77.2081\n"
                  "MOTOR_STATUS: M1=STOP M2=STOP M3=STALL M4=STOP\n"
                  "IMU1_LAST: 0.02,-0.01,-9.81 m/s^2\n"
                  "IMU2_LAST: 0.15,0.08,-9.45 m/s^2\n"
                  "ERROR_CODE: E433 — MOTOR_3_STALL\n"
                  "ERROR_CODE: E211 — IMU_MISMATCH\n"
                  "ERROR_CODE: E107 — RC_SIGNAL_LOST\n"
                  "FLASH_WRITE: PARTIAL — 3 of 5 pages\n").encode()
    files.append(("LOG/CRASH_DUMP.BIN", crash_dump, "added"))

    error_dump = ("[2026-06-22 14:31:15] WARN: RC RSSI dropped to -82 dBm\n"
                  "[2026-06-22 14:31:17] WARN: Packet loss 4/100 in 2s window\n"
                  "[2026-06-22 14:31:45] ERROR: IMU1-IMU2 Z-axis delta 0.24 m/s^2\n"
                  "[2026-06-22 14:32:01] ERROR: Motor 3 current surge 8.2A -> 14.7A\n"
                  "[2026-06-22 14:32:30] CRIT: ESC 3 stall detected\n"
                  "[2026-06-22 14:32:47] FATAL: Telemetry lost\n").encode()
    files.append(("SYS/ERROR_DUMP.log", error_dump, "added"))

    # RADIO - Modified RSSI log
    rssi_csv = "timestamp,channel,rssi_dbm,packet_loss\n"
    for i in range(180):
        t = i * 5
        rssi = -55 + (i % 25) * 0.8
        loss = 0 if i < 160 else (8 if i > 160 else 15 if i > 170 else 0)
        rssi_csv += f"T+{t//60:02d}:{t%60:02d},2.4GHz,{rssi:.1f},{loss}\n"
    files.append(("RADIO/RSSI_LOG.CSV", rssi_csv.encode(), "modified"))
    files.append(("RADIO/RC_COMMANDS.CSV", make_file_content("RC_COMMANDS.CSV"), "unchanged"))

    # SYS - Added error log, GPS almanac unchanged
    files.append(("SYS/GPS_ALMANAC.BIN", make_file_content("GPS_ALMANAC.BIN"), "unchanged"))

    # CAM - Settings modified (timestamp change)
    settings = ('<?xml version="1.0"?>\n<drone_settings>\n'
                '  <video_resolution>3840x2160</video_resolution>\n'
                '  <video_fps>30</video_fps>\n'
                '  <photo_format>JPEG</photo_format>\n'
                '  <white_balance>AUTO</white_balance>\n'
                '  <iso_range>100-6400</iso_range>\n'
                '  <ae_mode>PROGRAM</ae_mode>\n'
                '  <last_modified>2026-06-22T14:31:02Z</last_modified>\n'
                '</drone_settings>\n').encode()
    files.append(("CAM/SETTINGS.XML", settings, "modified"))
    files.append(("CAM/LENS_PROFILE.DAT", make_file_content("LENS_PROFILE.DAT"), "unchanged"))

    # BAT - Cell balance removed
    # (intentionally omitted)

    return files


def create_disk_image(filepath, file_list, label):
    """Create a zip-based disk image with realistic structure."""
    # Remove old file
    if os.path.exists(filepath):
        os.remove(filepath)

    manifest = {
        "image_type": "RAW",
        "filesystem": "FAT32 + exFAT",
        "partitions": 2,
        "label": label,
        "generated": datetime.now(timezone.utc).isoformat(),
        "total_files": 0,
        "total_size": 0,
        "files": []
    }

    with zipfile.ZipFile(filepath, 'w', zipfile.ZIP_DEFLATED) as z:
        for entry in file_list:
            if len(entry) == 2:
                path, content = entry
                status = "unchanged"
            else:
                path, content, status = entry

            # Write file content to zip
            z.writestr(path, content if isinstance(content, bytes) else content.encode())

            # Compute SHA1
            sha1 = hashlib.sha1(content if isinstance(content, bytes) else content.encode()).hexdigest()
            filetype = "unknown"
            ext = os.path.splitext(path)[1].lower()
            if ext == ".mp4": filetype = "MP4 video"
            elif ext == ".jpg": filetype = "JPEG image"
            elif ext == ".bin": filetype = "Binary data"
            elif ext == ".dat": filetype = "Flight log data"
            elif ext == ".cfg": filetype = "Configuration"
            elif ext == ".csv": filetype = "CSV data"
            elif ext == ".xml": filetype = "XML document"
            elif ext == ".log": filetype = "Log file"

            manifest["files"].append({
                "path": path,
                "size": len(content),
                "sha1": sha1,
                "filetype": filetype,
                "status": status
            })
            manifest["total_files"] += 1
            manifest["total_size"] += len(content)

        # Write manifest
        z.writestr("__manifest__.json", json.dumps(manifest, indent=2))

    size_mb = os.path.getsize(filepath) / (1024 * 1024)
    print(f"[OK] Created {label}: {filepath}")
    print(f"     Size: {size_mb:.1f} MB, Files: {manifest['total_files']}")
    return filepath


def main():
    print("=" * 60)
    print("  Drone Forensics Sample Disk Generator")
    print("=" * 60)

    # Generate baseline disk
    baseline_files = get_baseline_files()
    create_disk_image(BASELINE_DD,
                     [(p, c, "unchanged") for p, c in baseline_files],
                     "Drone Baseline (Pre-Crash)")

    print()

    # Generate crash disk
    crash_files = get_crash_files()
    create_disk_image(CRASH_DD, crash_files, "Drone Post-Crash (Recovered)")

    print()
    print(f"Files saved to: {OUTPUT_DIR}")
    print(f"  1. {BASELINE_DD}")
    print(f"  2. {CRASH_DD}")
    print()
    print("Upload these to the forensics dashboard for analysis.")
    print("=" * 60)

if __name__ == "__main__":
    main()
