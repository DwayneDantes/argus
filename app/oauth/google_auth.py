# app/oauth/google_auth.py (CORRECTED AND FINAL)

from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
# --- FIX 1: Import the correct exception library ---
from google.auth import exceptions as auth_exceptions
from pathlib import Path
import json

# The required scopes remain the same
SCOPES = [
    "https://www.googleapis.com/auth/drive.metadata.readonly",
    "https://www.googleapis.com/auth/drive.activity.readonly"
]
APP_DIR = Path.home() / ".argus"
TOKEN_FILE = APP_DIR / "token.json"
CLIENT_SECRET_FILE = Path("client_secret.json")

def get_credentials() -> Credentials:
    """
    Handles Google authentication for Argus.
    Gets valid credentials, handling the initial user login or refreshing an existing token.
    This version correctly handles scope changes by forcing re-authentication.
    """
    APP_DIR.mkdir(exist_ok=True)
    
    creds = None
    if TOKEN_FILE.exists():
        # Load credentials without specifying scopes here yet.
        # The scopes are stored within the token file itself.
        creds = Credentials.from_authorized_user_file(TOKEN_FILE)

    # --- FIX 2: Re-ordered logic. Check scopes BEFORE trying to refresh. ---
    # If a token exists but doesn't have ALL the required scopes, it's invalid.
    if creds and all(s in creds.scopes for s in SCOPES) is False:
        print("Required permissions have changed. Re-authentication is necessary.")
        TOKEN_FILE.unlink()  # Delete the outdated token
        creds = None
    # --- END of re-ordered logic ---

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                print("Refreshing expired credentials for Argus...")
                creds.refresh(Request())
            # --- FIX 3: Catch the correct exception type ---
            except auth_exceptions.RefreshError as e:
                print(f"Error refreshing token: {e}. Re-authentication is required.")
                TOKEN_FILE.unlink()
                creds = None
        
        if not creds:
            print("Performing first-time authentication for Argus...")
            if not CLIENT_SECRET_FILE.exists():
                raise FileNotFoundError(f"CRITICAL: client_secret.json not found. Please place it in the project root directory.")
            
            flow = InstalledAppFlow.from_client_secrets_file(str(CLIENT_SECRET_FILE), SCOPES)
            creds = flow.run_local_server(port=0)

        # Save the new or refreshed credentials with the correct scopes
        with open(TOKEN_FILE, 'w') as token:
            token.write(creds.to_json())
            print(f"Credentials for Argus saved to {TOKEN_FILE}")

    return creds