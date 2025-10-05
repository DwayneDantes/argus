# app/analysis/threat_scanner.py (FINAL, EFFICIENT BATCH VERSION)

import time
from datetime import datetime
from app.db import dao
from app.threat_intel import virustotal

# We wait 15 seconds between API calls. VT public API limit is 4 calls/minute.
SCAN_INTERVAL_SECONDS = 15 

def scan_unscanned_files():
    """
    Performs one cycle of threat scanning in batches, respecting API rate limits.
    It prioritizes new files but also works through the old backlog. It is 
    designed to be called repeatedly by a scheduler.
    """
    files_to_scan = []
    scan_type = "None"

    # This function opens its own connection, making it an independent task.
    with dao.get_db_connection() as conn:
        cursor = conn.cursor()

        # --- Tier 1: Prioritize a batch of recent files ---
        # We fetch a small batch (e.g., up to 4, to stay within a 1-min window)
        priority_files = dao.get_priority_unscanned_files(cursor, limit=4)
        if priority_files:
            files_to_scan = priority_files
            scan_type = "Priority"
        else:
            # --- Tier 2: If no new files, process a batch from the backlog ---
            backlog_files = dao.get_unscanned_files(cursor, limit=4)
            if backlog_files:
                files_to_scan = backlog_files
                scan_type = "Backlog"

        if not files_to_scan:
            print("GUARDIAN: [Scanner] No unscanned files found.")
            return

        print(f"GUARDIAN: [Scanner] Found {len(files_to_scan)} files to scan in '{scan_type}' queue.")
        
        for i, file_row in enumerate(files_to_scan):
            file_id = file_row['id']
            file_hash = file_row['md5Checksum']
            
            print(f"  > [{scan_type}] Scanning file {i+1}/{len(files_to_scan)} (hash: {file_hash})")
            report = virustotal.get_hash_report(file_hash)
            positives = 0
            if report and 'data' in report and 'attributes' in report['data']:
                stats = report['data']['attributes']['last_analysis_stats']
                positives = stats.get('malicious', 0) + stats.get('suspicious', 0)
                print(f"    - Result: {positives} positive detections.")
            
            dao.update_file_vt_score(cursor, file_id, positives)
            
            # --- CRITICAL: Wait *between* each API call in the batch ---
            if i < len(files_to_scan) - 1: # Don't wait after the last one
                time.sleep(SCAN_INTERVAL_SECONDS)

        # Commit all changes for the batch at the end of the transaction
        conn.commit()
        print(f"--- Threat Intelligence Scan Cycle Complete. {len(files_to_scan)} files processed. ---")