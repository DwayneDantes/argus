# app/threat_intel/virustotal.py (Updated to use .env)

import requests
import time
import os
from dotenv import load_dotenv

# This line will find the .env file in your project root and load its variables
load_dotenv()

# Read the API key from the environment variables
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# The base URL for the VirusTotal API v3
VT_API_URL = "https://www.virustotal.com/api/v3/files/"

def get_hash_report(file_hash: str) -> dict | None:
    """
    Fetches a file hash report from the VirusTotal API using a key from .env.
    """
    if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY == "PASTE_YOUR_API_KEY_HERE":
        print("  - WARNING: VIRUSTOTAL_API_KEY not found in .env file. Skipping threat intelligence scan.")
        return None

    url = f"{VT_API_URL}{file_hash}"
    headers = { "x-apikey": VIRUSTOTAL_API_KEY }

    try:
        response = requests.get(url, headers=headers)
        
        if response.status_code == 429: # Too Many Requests
            print("  - VirusTotal rate limit exceeded. Waiting 60 seconds...")
            time.sleep(60)
            response = requests.get(url, headers=headers)

        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"  - ERROR: Could not get VirusTotal report for hash {file_hash}: {e}")
        return None