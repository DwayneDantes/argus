# app/drive/ingest.py (Definitive Hierarchical Logic)
import json
from googleapiclient.discovery import build
# ... (rest of imports)
from googleapiclient.errors import HttpError
from google.oauth2.credentials import Credentials
from app.db import dao

# (The helper functions are unchanged)
def is_publicly_shared(permissions: list) -> bool:
    if not permissions: return False
    for perm in permissions:
        if perm.get('type') == 'anyone': return True
    return False

def is_externally_shared(permissions: list, user_email: str) -> bool:
    if not permissions: return False
    user_domain = user_email.split('@')[1]
    for perm in permissions:
        if perm.get('type') == 'anyone': return True
        if perm.get('type') == 'user' and 'emailAddress' in perm:
            email = perm.get('emailAddress')
            if email and user_domain not in email: return True
    return False

def ingest_once(creds: Credentials):
    # (The setup logic is unchanged)
    print("\n--- Starting Data Ingestion ---")
    service = build('drive', 'v3', credentials=creds)
    user_info = service.about().get(fields="user").execute()
    user_email = user_info['user']['emailAddress']
    page_token = dao.get_meta_value('startPageToken')
    if not page_token:
        response = service.changes().getStartPageToken().execute()
        page_token = response.get('startPageToken')
    
    with dao.get_db_connection() as conn:
        cursor = conn.cursor()
        checksum_cache = {}
        while page_token is not None:
            response = service.changes().list(pageToken=page_token, spaces='drive', fields='nextPageToken, newStartPageToken, changes(fileId, time)').execute()
            changes = response.get('changes', [])
            if not changes: print("No new changes found.")
            else:
                print(f"Found {len(changes)} new changes to process.")
                for change in changes:
                    # (Setup in loop is unchanged)
                    file_id = change.get('fileId')
                    change_time = change.get('time')
                    change_id = f"{file_id}-{change_time}"
                    
                    try:
                        fields = "id, name, mimeType, createdTime, modifiedTime, trashed, parents, lastModifyingUser, md5Checksum, permissions"
                        file_metadata = service.files().get(fileId=file_id, fields=fields).execute()
                        
                        event_type = None
                        permissions = file_metadata.get('permissions', [])
                        is_shared_now = is_externally_shared(permissions, user_email)
                        is_public_now = is_publicly_shared(permissions)

                        previous_details = dao.get_file_details(cursor, file_id)

                        # --- THIS IS THE NEW, CORRECT HIERARCHICAL LOGIC ---
                        if file_metadata.get('trashed'):
                            event_type = "file_trashed"
                        elif not previous_details:
                            # New file logic is unchanged
                            checksum = file_metadata.get('md5Checksum')
                            if checksum and (dao.find_file_by_checksum(cursor, checksum, file_id) or checksum in checksum_cache):
                                event_type = "file_copied"
                            else:
                                event_type = "file_created"
                        else:
                            # Logic for existing files, ordered by priority
                            was_public_before = previous_details['is_shared_publicly'] == 1
                            was_shared_before = previous_details['is_shared_externally'] == 1

                            if not was_public_before and is_public_now:
                                event_type = "file_made_public" # HIGHEST priority change
                            elif not was_shared_before and is_shared_now:
                                event_type = "file_shared_externally"
                            elif json.dumps(file_metadata.get('parents', [])) != previous_details['parents_json']:
                                event_type = "file_moved"
                            elif file_metadata.get('name') != previous_details['name']:
                                event_type = "file_renamed"
                            elif file_metadata.get('modifiedTime') != previous_details['modified_time']:
                                event_type = "file_modified"
                            else:
                                event_type = "permission_change_internal" # Lowest priority

                        if event_type:
                            # (Saving logic is almost the same, just pass the new public flag)
                            if file_metadata.get('md5Checksum'):
                                checksum_cache[file_metadata['md5Checksum']] = {'id': file_id, 'name': file_metadata.get('name')}
                            actor = file_metadata.get('lastModifyingUser')
                            actor_id = actor.get('permissionId') if actor else None
                            if actor: dao.save_user(cursor, actor)
                            dao.save_file(cursor, file_metadata, is_shared_now, is_public_now)
                            dao.save_event(cursor, change_id, file_id, event_type, actor_id, change_time, json.dumps(file_metadata))
                            actor_name = actor.get('displayName', 'Unknown') if actor else 'Unknown'
                            print(f"  - Stored Event: '{event_type}' for '{file_metadata.get('name')}' by {actor_name}")
                    except HttpError as error:
                        # (Error handling unchanged)
                        if error.resp.status == 404:
                            event_type = "file_deleted_permanently"
                            dao.save_event(cursor, f"{file_id}-{change_time}", file_id, event_type, None, change_time, '{}')
                            print(f"  - Stored Event: '{event_type}' for file {file_id}")
                        else:
                            print(f"  - Could not process file {file_id}: {error}")
            
            # (End of loop unchanged)
            conn.commit()
            page_token = response.get('nextPageToken')
            if not page_token:
                new_start_page_token = response.get('newStartPageToken')
                dao.set_meta_value("startPageToken", new_start_page_token)
                break
    print("--- Data Ingestion Complete ---")

# The scan_all_files function also needs to be updated to pass the new flag.
def scan_all_files(creds: Credentials):
    # ... (similar changes needed here, but let's focus on fixing ingest_once first)
    print("\n--- Starting Full Drive Scan (this may take a while)... ---")
    service = build('drive', 'v3', credentials=creds)
    user_info = service.about().get(fields="user").execute()
    user_email = user_info['user']['emailAddress']
    with dao.get_db_connection() as conn:
        cursor = conn.cursor()
        page_token = None
        file_count = 0
        while True:
            response = service.files().list(
                spaces='drive',
                fields='nextPageToken, files(id, name, mimeType, createdTime, modifiedTime, trashed, parents, owners, md5Checksum, permissions)',
                pageToken=page_token
            ).execute()
            files = response.get('files', [])
            if not files: break
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
                    permissions = file_metadata.get('permissions', [])
                    is_shared = is_externally_shared(permissions, user_email)
                    is_public = is_publicly_shared(permissions)
                    dao.save_file(cursor, file_metadata, is_shared, is_public)
                    event_type = 'file_created'
                    change_id = f"{file_id}-{file_metadata.get('createdTime')}"
                    dao.save_event(cursor, change_id, file_id, event_type, actor_id, file_metadata.get('createdTime'), json.dumps(file_metadata))
                    if file_count % 100 == 0:
                        print(f"  ...scanned {file_count} files so far...")
            page_token = response.get('nextPageToken', None)
            if page_token is None: break
        conn.commit()
    print(f"--- Full Drive Scan Complete. Cataloged a total of {file_count} files. ---")