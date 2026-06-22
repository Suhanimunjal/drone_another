#!/usr/bin/env python3
import os
import sys
import sqlite3
import argparse
import glob
import pandas as pd

class CommaSeparatedParser:
    def parse(self, file_path):
        df = pd.read_csv(file_path, dtype=str)
        df.fillna('nil', inplace=True)
        df['ORIGIN_FILE_SOURCE'] = os.path.basename(file_path)
        return df.to_dict(orient='records')

class ExcelSpreadsheetParser:
    def parse(self, file_path):
        compiled_rows = []
        try:
            xls = pd.ExcelFile(file_path, engine='openpyxl')
            for sheet in xls.sheet_names:
                df = pd.read_excel(file_path, sheet_name=sheet, dtype=str, engine='openpyxl')
                df.fillna('nil', inplace=True)
                df['ORIGIN_FILE_SOURCE'] = f"{os.path.basename(file_path)} [{sheet}]"
                compiled_rows.extend(df.to_dict(orient='records'))
        except Exception:
            pass
        return compiled_rows

class ForensicComparatorPipeline:
    def __init__(self, target_folder="database", db_name="drone_forensics.db"):
        self.folder_path = os.path.abspath(target_folder)
        self.db_name = db_name
        self.local_sheet_records = []
        self.csv_parser = CommaSeparatedParser()
        self.xlsx_parser = ExcelSpreadsheetParser()
        
        self.ingest_inventory_spreadsheets()

    def ingest_inventory_spreadsheets(self):
        """Sweeps local inventory sheets and standardizes row items for cross-comparison."""
        if not os.path.exists(self.folder_path):
            return
        
        target_files = ["drone_components_export.csv", "parrot.xlsx", "master_drone_output.csv", "drone_material_check_list.csv", "gfsu.xlsx"]
        
        for file_path in glob.glob(os.path.join(self.folder_path, "*")):
            f_name = os.path.basename(file_path)
            ext = os.path.splitext(file_path)[1].lower()
            
            if any(target.lower() in f_name.lower() for target in target_files) or ext in ['.csv', '.xlsx']:
                if f_name.startswith(("~", ".")) or "_telemetry" in f_name or "_remotegps" in f_name:
                    continue
                try:
                    records = self.xlsx_parser.parse(file_path) if ext in ['.xlsx', '.xls'] else self.csv_parser.parse(file_path)
                    for record in records:
                        normalized = {}
                        source_file = record.get('ORIGIN_FILE_SOURCE', 'Local Inventory')
                        
                        # Fix for squeezed columns: Detect if keys are actually comma-separated combinations
                        for k, v in record.items():
                            if ',' in str(k) and ',' in str(v):
                                keys_split = [x.strip().upper().replace(":", "").replace('"', '') for x in str(k).split(',')]
                                vals_split = [x.strip() for x in str(v).split(',')]
                                for sk, sv in zip(keys_split, vals_split):
                                    normalized[sk] = sv
                            else:
                                clean_key = str(k).strip().upper().replace(":", "").replace('"', '')
                                normalized[clean_key] = str(v).strip()
                        
                        normalized['ORIGIN_FILE_SOURCE'] = source_file
                        self.local_sheet_records.append(normalized)
                except Exception:
                    pass

    def execute_cross_comparison(self, search_term):
        """Queries the database and local spreadsheets to present a side-by-side comparison matrix."""
        term = str(search_term).strip().upper()
        
        # 1. Fetch Cloud Registry Nodes from SQLite
        conn = sqlite3.connect(self.db_name)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        db_term = f"%{search_term}%"
        cursor.execute('''
            SELECT DISTINCT m.* FROM master_registry m
            LEFT JOIN unified_attributes a ON m.DRONE_ID = a.DRONE_ID
            WHERE m.DRONE_ID LIKE ? OR m.MODEL_NAME LIKE ? OR m.MANUFACTURER LIKE ? OR a.ATTRIBUTE_VALUE LIKE ?
        ''', (db_term, db_term, db_term, db_term))
        db_rows = cursor.fetchall()
        conn.close()

        # 2. Filter Local Spreadsheet Inventory Files
        matching_sheets = []
        for record in self.local_sheet_records:
            if any(term in str(val).upper() for key, val in record.items() if key != 'ORIGIN_FILE_SOURCE'):
                matching_sheets.append(record)

        print("\n" + "="*95)
        print(f" UNIFIED CROSS-COMPARISON REPORT FOR KEYWORD: '{search_term}'")
        print("="*95)

        # DATA LAYER A
        print("\n[DATA LAYER A] -> CLOUD REPOSITORY IMAGE TRACES (DRIVE INTERFACE LINKED TO SQL)")
        print("-" * 95)
        if db_rows:
            for sqlite_row in db_rows:
                row = dict(sqlite_row)
                print(f"  * DRONE MODEL IDENTIFIER : {row.get('DRONE_ID', 'nil')}")
                print(f"  * DEVICE CLASSIFICATION  : {row.get('MODEL_NAME', 'nil')} (OEM: {row.get('MANUFACTURER', 'nil')})")
                print(f"  * PRIMARY OPTICAL CORE   : {row.get('CAMERA_SPECIFICATIONS', 'nil')}")
                print(f"  * STORAGE ARCHITECTURE   : {row.get('STORAGE_LOCATION_TYPE', 'nil')}")
                print(f"  * LIVE MEDIA DIRECTORY   : file://{row.get('MEDIA_FILES_PATH', 'nil')}")
                print(f"  * SYSTEM FLIGHT PATH TRACK: {row.get('GPS_CSV_PATH', 'nil')}")
                print(f"  * FLIGHT SENSOR DATALOG  : {row.get('TELEMETRY_CSV_PATH', 'nil')}")
                
                gps_path = row.get('GPS_CSV_PATH')
                if gps_path and os.path.exists(gps_path):
                    try:
                        gps_df = pd.read_csv(gps_path)
                        print(f"    [>] Current Flight GPS Fix sample:\n        {gps_df.iloc[0:1].to_dict(orient='records')}")
                    except Exception:
                        pass
                print()
        else:
            print("  [-] No matching telemetry traces found for this attribute inside the SQLite registry database.\n")

        # DATA LAYER B
        print("\n[DATA LAYER B] -> LOCAL SITE SHEET SPECIFICATION MATRIX (INVENTORY SPREADSHEETS DUMP)")
        print("-" * 95)
        if matching_sheets:
            for idx, sheet_item in enumerate(matching_sheets, 1):
                source = sheet_item.get('ORIGIN_FILE_SOURCE', 'Local Inventory')
                print(f"  [{idx}] Entry Log Match Source: {source}")
                
                drone_id = sheet_item.get('DRONE ID', sheet_item.get('DRONE_ID', sheet_item.get('ITEM ID', 'nil')))
                model_name = sheet_item.get('MODEL NAME', sheet_item.get('MODEL_NAME', 'nil'))
                manufacturer = sheet_item.get('COMPANY', sheet_item.get('MANUFACTURER', 'nil'))
                
                print(f"      - Extracted Model Key: {model_name} (ID Reference: {drone_id})")
                if manufacturer != 'nil':
                    print(f"      - Manufacturer       : {manufacturer}")
                
                skip_keys = ['DRONE ID', 'DRONE_ID', 'ITEM ID', 'MODEL NAME', 'MODEL_NAME', 'COMPANY', 'MANUFACTURER', 'ORIGIN_FILE_SOURCE']
                for key, val in sheet_item.items():
                    if key in skip_keys or val.lower() in ['nil', 'nan', '']:
                        continue
                    clean_label = key.replace('_', ' ')
                    print(f"      - {clean_label:<25}: {val}")
                print()
        else:
            print("  [-] No matching data logs found for this model token across your local sheets archive.\n")
        print("="*95 + "\n")

def main():
    parser = argparse.ArgumentParser(description="Unified Forensic Comparative Analysis Engine.")
    parser.add_argument('-q', '--query', default='CIV-DJI-P4P', help='The Model Name or Drone ID used for cross-layer data verification.')
    args = parser.parse_args()

    pipeline = ForensicComparatorPipeline()
    pipeline.execute_cross_comparison(args.query)

if __name__ == "__main__":
    main()
