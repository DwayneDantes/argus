# app/threat_intel/virustotal.py (FIXED - Quieter 404 Handling)

import requests
import time
import os
from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VT_API_URL = "https://www.virustotal.com/api/v3/files/"

def get_hash_report(file_hash: str) -> dict | None:
    """
    Fetches a file hash report from the VirusTotal API.
    Returns None if file not found (404) - this is normal and expected.
    """
    if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY == "PASTE_YOUR_API_KEY_HERE":
        # Only print this warning once per session
        if not hasattr(get_hash_report, '_warned'):
            print("  - WARNING: VIRUSTOTAL_API_KEY not configured. Skipping threat scans.")
            get_hash_report._warned = True
        return None

    url = f"{VT_API_URL}{file_hash}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        response = requests.get(url, headers=headers)
        
        # 404 is normal - file not in VT database. Don't print error.
        if response.status_code == 404:
            return None
        
        # Rate limiting
        if response.status_code == 429:
            print("  - VirusTotal rate limit hit. Waiting 60 seconds...")
            time.sleep(60)
            response = requests.get(url, headers=headers)
        
        response.raise_for_status()
        return response.json()
        
    except requests.exceptions.HTTPError as e:
        # Only log non-404 HTTP errors
        if e.response.status_code != 404:
            print(f"  - ERROR: VirusTotal API error for {file_hash}: {e}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"  - ERROR: Network error accessing VirusTotal: {e}")
        return None