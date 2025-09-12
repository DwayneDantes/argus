# app/drive/ingest.py (Final, Corrected Version with Robust Logic)

import json
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.oauth2.credentials import Credentials
from app.db import dao

def ingest_once(creds: Credentials):
    """
    Performs a one-time ingestion with robust logic for trash, copy, and
    event detection, storing all data in the local database.
    """
    print("\n--- Starting Data Ingestion (Robust Logic) ---")
    service = build('drive', 'v3', credentials=creds)

    page_token = dao.get_meta_value('startPageToken')
    if not page_token:
        print("No previous page token found. Fetching a new one.")
        response = service.changes().getStartPageToken().execute()
        page_token = response.get('startPageToken')
    else:
        print(f"Resuming from saved page token: {page_token}")

    with dao.get_db_connection() as conn:
        cursor = conn.cursor()
        
        # In-memory cache for checksums processed in THIS batch.
        checksum_cache = {}

        while page_token is not None:
            print("Fetching changes...")
            response = service.changes().list(
                pageToken=page_token, spaces='drive',
                fields='nextPageToken, newStartPageToken, changes(fileId, time)' # We only need fileId and time
            ).execute()

            changes = response.get('changes', [])
            if not changes:
                print("No new changes found.")
            else:
                print(f"Found {len(changes)} new changes to process and store.")

                for change in changes:
                    file_id = change.get('fileId')
                    change_time = change.get('time')
                    change_id = f"{file_id}-{change_time}"
                    
                    try:
                        # Step 1: Always get the full "dossier" of metadata first.
                        fields = "id, name, mimeType, createdTime, modifiedTime, trashed, parents, lastModifyingUser, md5Checksum"
                        file_metadata = service.files().get(fileId=file_id, fields=fields).execute()
                        
                        event_type = None

                        # Step 2: The first and most important check is for trashed status.
                        if file_metadata.get('trashed'):
                            event_type = "file_trashed"
                        else:
                            # If not trashed, proceed with other logic.
                            previous_details = dao.get_file_details(cursor, file_id)
                            
                            if not previous_details:
                                checksum = file_metadata.get('md5Checksum')
                                if checksum:
                                    # Check the database AND the in-memory cache for copies.
                                    existing_copy = dao.find_file_by_checksum(cursor, checksum, file_id)
                                    if existing_copy:
                                        event_type = "file_copied"
                                        file_metadata['copiedFrom'] = {'id': existing_copy['id'], 'name': existing_copy['name']}
                                    elif checksum in checksum_cache:
                                        event_type = "file_copied"
                                        original_file = checksum_cache[checksum]
                                        file_metadata['copiedFrom'] = {'id': original_file['id'], 'name': original_file['name']}
                                    else:
                                        event_type = "file_created"
                                else:
                                    event_type = "file_created"
                            else:
                                # Logic for existing files (move, rename, modify)
                                if json.dumps(file_metadata.get('parents', [])) != previous_details['parents_json']:
                                    event_type = "file_moved"
                                elif file_metadata.get('name') != previous_details['name']:
                                    event_type = "file_renamed"
                                elif file_metadata.get('modifiedTime') != previous_details['modified_time']:
                                    event_type = "file_modified"
                                else:
                                    print(f"  - Ignoring non-critical metadata update for '{file_metadata.get('name')}'")
                                    continue
                        
                        # Add the current file to our in-memory cache for this run.
                        if file_metadata.get('md5Checksum'):
                            checksum_cache[file_metadata['md5Checksum']] = {'id': file_id, 'name': file_metadata.get('name')}

                        # Save everything to the database
                        actor = file_metadata.get('lastModifyingUser')
                        actor_id = None
                        if actor:
                            actor_id = actor.get('permissionId')
                            dao.save_user(cursor, actor)
                        
                        dao.save_file(cursor, file_metadata)
                        dao.save_event(cursor, change_id, file_id, event_type, actor_id, change_time, json.dumps(file_metadata))
                        
                        actor_name = actor.get('displayName', 'Unknown') if actor else 'Unknown'
                        print(f"  - Stored Event: '{event_type}' for '{file_metadata.get('name')}' by {actor_name}")

                    except HttpError as error:
                        # A 404 error here means the file was permanently deleted, not just trashed.
                        if error.resp.status == 404:
                            event_type = "file_deleted_permanently"
                            dao.save_event(cursor, change_id, file_id, event_type, None, change_time, '{}')
                            print(f"  - Stored Event: '{event_type}' for file {file_id}")
                        else:
                            print(f"  - Could not process file {file_id}: {error}")

            conn.commit()

            if 'nextPageToken' in response:
                page_token = response.get('nextPageToken')
            else:
                new_start_page_token = response.get('newStartPageToken')
                print(f"\nIngestion complete. Saving new start page token: {new_start_page_token}")
                dao.set_meta_value("startPageToken", new_start_page_token)
                break
    
    print("--- Data Ingestion Complete ---")