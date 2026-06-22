# Drone Forensics Dashboard

A browser-based forensic analysis workstation for comparing baseline (pre-crash) vs post-crash drone disk images. Uses real SQLite databases, CSV inventories, and disk image differential analysis.

## Architecture

```
forensics_dashboard.html   ← Single-file GUI (no build tools)
        ↕  REST API + SSE
backend_server.py          ← Flask backend on localhost:5000
        ↕
generate_drone_samples.py  ← Creates .dd sample disk images
Drone-DATABASE/            ← SQLite DB + CSV inventory sheets
```

## Quick Start

### 1. Install dependencies

```powershell
pip install flask flask-cors
```

### 2. (Optional) Generate fresh sample disk images

```powershell
python generate_drone_samples.py
```

This creates:
- `drone_baseline.dd` — 132 files, healthy pre-crash SD card
- `drone_crash.dd` — 110 files, post-crash with 24 files removed, 4 modified, 2 crash artifacts

### 3. Start the backend

```powershell
python backend_server.py
```

The server starts on `http://localhost:5000` and auto-creates an `uploads/` directory for uploaded files.

### 4. Open the dashboard

Open `forensics_dashboard.html` in any modern browser (Chrome, Edge, Firefox).

### 5. Run analysis

**With backend (live mode):**
1. Go to the **Ingest** tab
2. Click **Load Sample Baseline** to load the pre-crash disk image
3. Click **Load Sample Crash** to load the post-crash image
4. Watch the live extraction pipeline log stream in real time (9 stages, per-file status)
5. Click **Run Analysis** to cross-compare both images
6. All tabs populate with real comparison data

**Without backend (demo mode):**
The dashboard loads fully hardcoded demo data from the SQLite database schema. All tabs are pre-populated on page load.

## What each tab does

| Tab | Description |
|-----|-------------|
| **OV — Overview** | KPI cards (matched components, changed files, data recovered, anomalies) + attribute comparison matrix |
| **IN — Ingest** | Upload physical photos (before/after) and disk images (before/after), live extraction pipeline log |
| **FC — Flight Controller** | Baseline FC parameters vs post-crash FC recovery status with per-component color coding |
| **DD — Disk Diff** | Sector integrity bar (intact/corrupt/unreadable) + filesystem change diff listing |
| **EX — Extraction** | 12 artifact types with recovery statuses (Complete/Partial/Lost/Crash Artifact) |
| **TL — Timeline** | 10 reconstructed flight events with anomaly markers |

## API endpoints (backend)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/status` | Backend health + loaded state |
| POST | `/api/upload/baseline` | Upload pre-crash .dd file |
| POST | `/api/upload/crash` | Upload post-crash .dd file |
| POST | `/api/load-sample/<name>` | Load pre-generated sample |
| POST | `/api/analyze` | Run cross-comparison analysis |
| GET | `/api/comparison` | Get cached comparison result |
| GET | `/api/analysis/<metric>` | Get specific metric (kpi, overview, diskdiff, extraction, timeline) |
| GET | `/api/extraction/log` | SSE stream of real-time extraction log |
| POST | `/api/clear` | Reset all state |

## Database schema

The hardcoded data mirrors the real `drone_forensics.db`:
- **master_registry** — 4 drone entries (Phantom 4 Pro, Mavic 3 Pro, MQ-4C Triton, Anafi Thermal)
- **unified_attributes** — 11 attribute records (chipset, firmware, storage, battery, etc.)
- **drone_components_export.csv** — 7 baseline components for Mavic 3 Pro

## Sample disk image structure

Both `.dd` files are ZIP-based archives containing a realistic drone microSD card layout:

```
DCIM/100MEDIA/     ← MP4 videos + JPG photos
MISC/              ← Flight DAT logs + PARAM.CFG
LOG/               ← Binary flight logs + crash dump
RADIO/             ← RSSI + RC command CSVs
SYS/               ← GPS almanac + error dump
CAM/               ← Camera settings + lens profile
BAT/               ← Battery cell balance logs
__manifest__.json  ← File inventory with SHA1 hashes
```

The crash image differs from baseline by: removing 24 files, modifying PARAM.CFG and RSSI logs (CRC mismatches), adding CRASH_DUMP.BIN and ERROR_DUMP.log artifacts.
