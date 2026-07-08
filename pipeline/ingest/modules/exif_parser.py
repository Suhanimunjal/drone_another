"""C5 — EXIF Metadata Parser.

Reads EXIF GPS and metadata from image files (JPG, DNG, etc.)
and emits TSK_EXIF_DATA artifacts for geo-located photos.
"""

import os
from datetime import datetime
from ..base import IngestModule, Artifact


class ExifParserModule(IngestModule):
    name = "exif_parser"
    depends_on = []
    applies_to = "specific_extension"
    supported_types = [".jpg", ".jpeg", ".png", ".dng", ".tiff", ".tif"]

    def run(self, file_manifest_row=None, case_context=None, log_cb=None):
        if not file_manifest_row:
            return []

        file_path = file_manifest_row.get("extracted_path")
        case_id = file_manifest_row.get("case_id")
        file_id = file_manifest_row.get("id")
        rel_path = file_manifest_row.get("path", "")

        if not file_path or not os.path.isfile(file_path):
            return []

        try:
            from PIL import Image
            from PIL.ExifTags import TAGS, GPSTAGS
        except ImportError:
            return []

        try:
            img = Image.open(file_path)
            exif_raw = img.getexif()
            if not exif_raw:
                return []
        except Exception:
            return []

        exif = {}
        for tag_id, value in exif_raw.items():
            tag_name = TAGS.get(tag_id, tag_id)
            exif[tag_name] = value

        gps_info = {}
        gps_raw = exif_raw.get_ifd(0x8825)
        if gps_raw:
            for tag_id, value in gps_raw.items():
                tag_name = GPSTAGS.get(tag_id, tag_id)
                gps_info[tag_name] = value

        def _to_decimal(dms, ref):
            try:
                d, m, s = [float(x) for x in dms]
                result = d + m / 60.0 + s / 3600.0
                if ref in ("S", "W"):
                    result = -result
                return round(result, 7)
            except (TypeError, ValueError):
                return None

        lat = None
        lon = None
        if "GPSLatitude" in gps_info and "GPSLatitudeRef" in gps_info:
            lat = _to_decimal(gps_info["GPSLatitude"], gps_info["GPSLatitudeRef"])
        if "GPSLongitude" in gps_info and "GPSLongitudeRef" in gps_info:
            lon = _to_decimal(gps_info["GPSLongitude"], gps_info["GPSLongitudeRef"])

        if lat is None and lon is None:
            return []

        ts_ref = None
        for key in ("DateTimeOriginal", "DateTimeDigitized", "DateTime"):
            if key in exif:
                try:
                    dt = datetime.strptime(str(exif[key]), "%Y:%m:%d %H:%M:%S")
                    ts_ref = dt.isoformat()
                    break
                except ValueError:
                    continue

        details = {
            "make": exif.get("Make"),
            "model": exif.get("Model"),
            "datetime_original": str(exif.get("DateTimeOriginal", "")),
            "gps": gps_info,
            "image_width": exif.get("ExifImageWidth"),
            "image_height": exif.get("ExifImageHeight"),
            "orientation": exif.get("Orientation"),
        }

        return [
            Artifact(
                artifact_type="TSK_EXIF_DATA",
                case_id=case_id,
                module_name=self.name,
                file_id=file_id,
                title=f"Geo-tagged image: {os.path.basename(rel_path)}",
                description=f"{exif.get('Make','')} {exif.get('Model','')} @ ({lat}, {lon})",
                details=details,
                ts_ref=ts_ref,
                lat=lat,
                lon=lon,
            )
        ]
