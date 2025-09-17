# app/drive/ingest.py (Complete and Verified)

import json
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.oauth2.credentials import Credentials
from app.db import dao

# --- HELPER FUNCTION for permission analysis ---
def is_externally_shared(permissions: list, user_email: str) -> bool:
    """
    Analyzes a file's permissions list to see if it's shared externally.
    """
    if not permissions:
        return False
    
    user_domain = user_email.split('@')[1]

    for perm in permissions:
        if perm.get('type') == 'anyone':
            return True
        if perm.get('type') == 'user' and 'emailAddress' in perm:
            email = perm.get('emailAddress')
            if email and user_domain not in email:
                return True
    return False

# --- MAIN INGESTION FUNCTION for daily updates ---
def ingest_once(creds: Credentials):
    """
    Performs a one-time ingestion, including permission analysis.
    """
    print("\n--- Starting Data Ingestion ---")
    service = build('drive', 'v3', credentials=creds)

    user_info = service.about().get(fields="user").execute()
    user_email = user_info['user']['emailAddress']

    page_token = dao.get_meta_value('startPageToken')
    if not page_token:
        print("No previous page token found. Fetching a new one.")
        response = service.changes().getStartPageToken().execute()
        page_token = response.get('startPageToken')
    else:
        print(f"Resuming from saved page token: {page_token}")

    with dao.get_db_connection() as conn:
        cursor = conn.cursor()
        checksum_cache = {}

        while page_token is not None:
            print("Fetching changes...")
            response = service.changes().list(
                pageToken=page_token, spaces='drive',
                fields='nextPageToken, newStartPageToken, changes(fileId, time)'
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
                        fields = "id, name, mimeType, createdTime, modifiedTime, trashed, parents, lastModifyingUser, md5Checksum, permissions"
                        file_metadata = service.files().get(fileId=file_id, fields=fields).execute()
                        
                        event_type = None
                        permissions = file_metadata.get('permissions', [])
                        is_shared = is_externally_shared(permissions, user_email)

                        if file_metadata.get('trashed'):
                            event_type = "file_trashed"
                        else:
                            previous_details = dao.get_file_details(cursor, file_id)
                            
                            if not previous_details:
                                checksum = file_metadata.get('md5Checksum')
                                if checksum:
                                    existing_copy = dao.find_file_by_checksum(cursor, checksum, file_id)
                                    if existing_copy or checksum in checksum_cache:
                                        event_type = "file_copied"
                                    else:
                                        event_type = "file_created"
                                else:
                                    event_type = "file_created"
                            else:
                                if previous_details['is_shared_externally'] == 0 and is_shared:
                                    event_type = "file_shared_externally"
                                elif json.dumps(file_metadata.get('parents', [])) != previous_details['parents_json']:
                                    event_type = "file_moved"
                                elif file_metadata.get('name') != previous_details['name']:
                                    event_type = "file_renamed"
                                elif file_metadata.get('modifiedTime') != previous_details['modified_time']:
                                    event_type = "permission_change_internal"
                        
                        if file_metadata.get('md5Checksum'):
                            checksum_cache[file_metadata['md5Checksum']] = {'id': file_id, 'name': file_metadata.get('name')}

                        actor = file_metadata.get('lastModifyingUser')
                        actor_id = None
                        if actor:
                            actor_id = actor.get('permissionId')
                            dao.save_user(cursor, actor)
                        
                        dao.save_file(cursor, file_metadata, is_shared)
                        dao.save_event(cursor, change_id, file_id, event_type, actor_id, change_time, json.dumps(file_metadata))
                        
                        actor_name = actor.get('displayName', 'Unknown') if actor else 'Unknown'
                        print(f"  - Stored Event: '{event_type}' for '{file_metadata.get('name')}' by {actor_name}")

                    except HttpError as error:
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
                print(f"\nIngestion complete. Saving new start page token for next run: {new_start_page_token}")
                dao.set_meta_value("startPageToken", new_start_page_token)
                break
    
    print("--- Data Ingestion Complete ---")

# --- FULL INVENTORY FUNCTION for the initial baseline scan ---
def scan_all_files(creds: Credentials):
    """
    Performs a full inventory of every file in the user's Drive.
    """
    print("\n--- Starting Full Drive Scan (this may take a while)... ---")
    service = build('drive', 'v3', credentials=creds)

    # We need the user's email for the permission analysis helper
    user_info = service.about().get(fields="user").execute()
    user_email = user_info['user']['emailAddress']

    with dao.get_db_connection() as conn:
        cursor = conn.cursor()
        page_token = None
        file_count = 0

        while True:
            print(f"Fetching a page of files...")
            # Request permissions during the full scan as well
            response = service.files().list(
                spaces='drive',
                fields='nextPageToken, files(id, name, mimeType, createdTime, modifiedTime, trashed, parents, owners, md5Checksum, permissions)',
                pageToken=page_token
            ).execute()

            files = response.get('files', [])
            if not files:
                print("No files found on this page.")
            else:
                for file_metadata in files:
                    file_count += 1
                    file_id = file_metadata.get('id')

                    actor = file_metadata.get('owners', [{}])[0]
                    actor_id = None
                    if actor:
                        actor['permissionId'] = actor.get('permissionId') or actor.get('id')
                        actor_id = actor.get('permissionId')
                        dao.save_user(cursor, actor)

                    # Determine sharing status before saving
                    permissions = file_metadata.get('permissions', [])
                    is_shared = is_externally_shared(permissions, user_email)
                    dao.save_file(cursor, file_metadata, is_shared)
                    
                    event_type = 'file_created'
                    change_id = f"{file_id}-{file_metadata.get('createdTime')}"
                    dao.save_event(cursor, change_id, file_id, event_type, actor_id, file_metadata.get('createdTime'), json.dumps(file_metadata))
                    
                    if file_count % 100 == 0:
                        print(f"  ...scanned {file_count} files so far...")

            page_token = response.get('nextPageToken', None)
            if page_token is None:
                break

        conn.commit()

    print(f"--- Full Drive Scan Complete. Cataloged a total of {file_count} files. ---")
    print("The baseline is now established. You can now use '--ingest-once' for daily updates.")