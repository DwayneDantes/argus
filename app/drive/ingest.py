# app/drive/ingest.py (Final Reconnaissance Version with Event Inference)

from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.oauth2.credentials import Credentials
from app.db import dao

def ingest_once(creds: Credentials):
    """
    Performs a one-time scan, fetches comprehensive metadata, and demonstrates
    how we can INFER specific event types from the raw API data.
    """
    print("\n--- Starting Data Reconnaissance with Event Inference ---")
    service = build('drive', 'v3', credentials=creds)

    page_token = dao.get_meta_value('startPageToken')
    if not page_token:
        print("No previous page token found. Fetching a new one.")
        response = service.changes().getStartPageToken().execute()
        page_token = response.get('startPageToken')
    else:
        print(f"Resuming from saved page token: {page_token}")

    print("Fetching changes...")
    response = service.changes().list(
        pageToken=page_token,
        spaces='drive',
        fields='nextPageToken, newStartPageToken, changes(fileId, removed)'
    ).execute()

    changes = response.get('changes', [])
    if not changes:
        print("No new changes found.")
        return

    print(f"Found {len(changes)} changes. Analyzing each to infer the event type...")

    for change in changes:
        file_id = change.get('fileId')
        inferred_event_type = "unknown" # Start with a default

        print("\n" + "="*50)
        print(f"Analyzing Change for File ID: {file_id}")
        print("="*50)

        # --- THIS IS THE DETECTIVE LOGIC ---

        # Clue 1: Was the file removed?
        if change.get('removed'):
            inferred_event_type = "file_trashed"
            print(f">>> INFERRED EVENT: {inferred_event_type} <<<")
            print("    This is a direct signal from the API.")
            continue # Nothing more to investigate

        # If not removed, we need more details to infer the event.
        try:
            fields_to_request = "name, parents, modifiedTime, createdTime"
            file_metadata = service.files().get(fileId=file_id, fields=fields_to_request).execute()

            # Clue 2: Is the creation time the same as the modification time?
            # (Note: This is a good heuristic, not 100% foolproof)
            created_time = file_metadata.get('createdTime')
            modified_time = file_metadata.get('modifiedTime')
            
            # To be more robust, we'd check if the fileId exists in our DB.
            # For this demo, we'll print what we would do.
            print("--- Inference Clues ---")
            print(f"  - Created Time:  {created_time}")
            print(f"  - Modified Time: {modified_time}")
            print(f"  - Parent Folder(s): {file_metadata.get('parents')}")
            
            # SIMULATED LOGIC: In a real run, we would compare these values to our database.
            # if file_id not in database:
            #     inferred_event_type = "file_created"
            # elif new_parents != stored_parents:
            #     inferred_event_type = "file_moved"
            # elif new_modifiedTime != stored_modifiedTime:
            #     inferred_event_type = "file_modified"
            # else:
            #     inferred_event_type = "permission_change" # Or another metadata change

            # For this demonstration, we'll just label it as modified.
            inferred_event_type = "file_modified (or created/moved/permission_change)"

            print(f"\n>>> INFERRED EVENT: {inferred_event_type} <<<")
            print(f"    File Name: '{file_metadata.get('name')}'")
            print("    (To be more specific, we would compare the clues above to our database records)")


        except HttpError as error:
            print(f"!!! Could not retrieve metadata for file {file_id}: {error} !!!")


    print("\n" + "="*50)
    print("Reconnaissance complete. You can see how we will infer events.")