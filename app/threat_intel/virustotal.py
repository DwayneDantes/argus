# app/threat_intel/virustotal.py (Correct and Final)

import requests
import time
from config import VIRUSTOTAL_API_KEY

VT_API_URL = "https://www.virustotal.com/api/v3/files/"

# --- CORRECTED FUNCTION DEFINITION ---
# It only needs the hash. It gets the key from the import above.
def get_hash_report(file_hash: str) -> dict | None:
    """
    Fetches a file hash report from the VirusTotal API.
    """
    if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY == "PASTE_YOUR_API_KEY_HERE":
        print("  - WARNING: VirusTotal API key not configured in config.py. Skipping scan.")
        return None

    url = f"{VT_API_URL}{file_hash}"
    headers = { "x-apikey": VIRUSTOTAL_API_KEY }

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 429:
            print("  - VirusTotal rate limit exceeded. Waiting 60 seconds...")
            time.sleep(60)
            response = requests.get(url, headers=headers)
        
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"  - ERROR: Could not get VirusTotal report for hash {file_hash}: {e}")
        return None