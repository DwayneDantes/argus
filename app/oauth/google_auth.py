# app/oauth/google_auth.py (CORRECTED)

from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google.api_core import exceptions
from pathlib import Path
import json

# --- CONFIGURATION ---
SCOPES = ["https://www.googleapis.com/auth/drive.metadata.readonly"]
APP_DIR = Path.home() / ".argus"
TOKEN_FILE = APP_DIR / "token.json"
CLIENT_SECRET_FILE = Path("client_secret.json")

def get_credentials() -> Credentials:
    """
    Handles Google authentication for Argus.
    Gets valid credentials, handling the initial user login or refreshing an existing token.
    """
    APP_DIR.mkdir(exist_ok=True)
    
    creds = None
    if TOKEN_FILE.exists():
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                print("Refreshing expired credentials for Argus...")
                creds.refresh(Request())
            except exceptions.RefreshError as e:
                print(f"Error refreshing token: {e}. Re-authentication is required.")
                TOKEN_FILE.unlink()
                creds = None
        
        if not creds:
            print("Performing first-time authentication for Argus...")
            if not CLIENT_SECRET_FILE.exists():
                raise FileNotFoundError(f"CRITICAL: client_secret.json not found. Please place it in the project root directory.")
            
            flow = InstalledAppFlow.from_client_secrets_file(str(CLIENT_SECRET_FILE), SCOPES)
            creds = flow.run_local_server(port=0)

        with open(TOKEN_FILE, 'w') as token:
            token.write(creds.to_json())
            print(f"Credentials for Argus saved to {TOKEN_FILE}")

    return creds