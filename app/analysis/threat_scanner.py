# app/analysis/threat_scanner.py (Corrected and Final)

import time
from datetime import datetime

# Import the DAO functions and the VT handler
from app.db import dao
from app.threat_intel import virustotal

# The VirusTotal free API allows 4 requests per minute.
# To be safe, we will make one request every 20 seconds.
SCAN_INTERVAL_SECONDS = 20

def scan_unscanned_files():
    """
    The main function for the slow, background threat scan.
    """
    print("\n--- Starting Threat Intelligence Scan ---")
    print(f"Checking for unscanned files... (Respecting API limits: 1 scan per {SCAN_INTERVAL_SECONDS} seconds)")

    with dao.get_db_connection() as conn:
        cursor = conn.cursor()

        # Get a batch of files that need to be scanned
        files_to_scan = dao.get_unscanned_files(cursor)

        if not files_to_scan:
            print("No new files to scan. The database is up-to-date.")
            return

        print(f"Found {len(files_to_scan)} unscanned files. Beginning scan...")
        scanned_count = 0
        
        for file_row in files_to_scan:
            file_id = file_row['id']
            file_hash = file_row['md5Checksum']
            
            print(f"  > Scanning hash: {file_hash} (for file ID: {file_id})")
            
            # --- CORRECTED LINE ---
            # Call the VirusTotal API handler without the non-existent api_key variable
            report = virustotal.get_hash_report(file_hash)
            
            positives = 0
            if report and 'data' in report and 'attributes' in report['data']:
                stats = report['data']['attributes']['last_analysis_stats']
                positives = stats.get('malicious', 0) + stats.get('suspicious', 0)
                print(f"    - Result: {positives} positive detections.")
            else:
                print("    - Result: Hash not found in VirusTotal database or an error occurred.")

            # Save the result to our database
            dao.update_file_vt_score(cursor, file_id, positives)
            conn.commit()
            scanned_count += 1

            # Crucially, wait before the next scan to respect the rate limit
            if len(files_to_scan) > scanned_count:
                time.sleep(SCAN_INTERVAL_SECONDS)

        print(f"\n--- Threat Intelligence Scan Complete. Scanned {scanned_count} files. ---")