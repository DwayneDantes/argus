# app/analysis/threat_scanner.py (Upgraded with Priority Scanning)

import time
from datetime import datetime
from app.db import dao
from app.threat_intel import virustotal

SCAN_INTERVAL_SECONDS = 20

def scan_unscanned_files():
    """
    Main function for threat scanning, now with a two-tiered priority system.
    """
    print("\n--- Starting Threat Intelligence Scan (with Priority) ---")
    
    with dao.get_db_connection() as conn:
        cursor = conn.cursor()

        # --- TIER 1: Scan recent, high-priority files first ---
        print("Checking for new, high-priority files to scan...")
        priority_files = dao.get_priority_unscanned_files(cursor)

        if priority_files:
            print(f"Found {len(priority_files)} new files. Scanning them first...")
            for file_row in priority_files:
                # (The scanning logic is the same as before)
                file_id = file_row['id']
                file_hash = file_row['md5Checksum']
                print(f"  > [Priority] Scanning hash: {file_hash}")
                report = virustotal.get_hash_report(file_hash)
                positives = 0
                if report and 'data' in report and 'attributes' in report['data']:
                    stats = report['data']['attributes']['last_analysis_stats']
                    positives = stats.get('malicious', 0) + stats.get('suspicious', 0)
                    print(f"    - Result: {positives} positive detections.")
                else:
                    print("    - Result: Hash not found in VT database or an error occurred.")
                dao.update_file_vt_score(cursor, file_id, positives)
                conn.commit()
                # We still wait to respect the rate limit
                time.sleep(SCAN_INTERVAL_SECONDS)
        else:
            print("No high-priority files found.")

        # --- TIER 2: Scan the older backlog of files ---
        print("\nChecking for older, backlog files to scan...")
        # We'll just scan one from the backlog per run to keep it slow and steady
        backlog_files = dao.get_unscanned_files(cursor, limit=1)

        if not backlog_files:
            print("No backlog files to scan. The database is fully up-to-date.")
            return

        print("Found an older file in the backlog. Scanning it now...")
        for file_row in backlog_files:
            # (The scanning logic is the same as before)
            file_id = file_row['id']
            file_hash = file_row['md5Checksum']
            print(f"  > [Backlog] Scanning hash: {file_hash}")
            report = virustotal.get_hash_report(file_hash)
            positives = 0
            if report and 'data' in report and 'attributes' in report['data']:
                stats = report['data']['attributes']['last_analysis_stats']
                positives = stats.get('malicious', 0) + stats.get('suspicious', 0)
                print(f"    - Result: {positives} positive detections.")
            else:
                print("    - Result: Hash not found in VT database or an error occurred.")
            dao.update_file_vt_score(cursor, file_id, positives)
            conn.commit()
            time.sleep(SCAN_INTERVAL_SECONDS)

    print("\n--- Threat Intelligence Scan Cycle Complete. ---")