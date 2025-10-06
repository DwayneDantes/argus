# app/drive/ingest.py (FIXED - Better First-Run Handling)

import json
from datetime import datetime, timezone, timedelta
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.oauth2.credentials import Credentials
from app.db import dao

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
    print("\n--- Starting Hybrid Data Ingestion (Activity API + Changes API) ---")
    
    drive_v3_service = build('drive', 'v3', credentials=creds)
    activity_v2_service = build('driveactivity', 'v2', credentials=creds)
    
    user_info = drive_v3_service.about().get(fields="user").execute()
    user_email = user_info['user']['emailAddress']

    with dao.get_db_connection() as conn:
        cursor = conn.cursor()

        print("\n[Phase 1] Querying Drive Activity API for definitive events...")
        last_ingest_ts = dao.get_meta_value(cursor, 'last_activity_timestamp')
        
        # FIXED: Better first-run handling with clearer messaging
        if not last_ingest_ts:
            # Start from 10 minutes ago on first run
            last_ingest_ts = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
            dao.set_meta_value(cursor, 'last_activity_timestamp', last_ingest_ts)
            conn.commit()
            print(f"First-time ingestion. Starting from: {last_ingest_ts}")
        else:
            print(f"Resuming from last checkpoint: {last_ingest_ts}")

        timestamp_ms = int(datetime.fromisoformat(last_ingest_ts).timestamp() * 1000)
        request = {'filter': f"time > {timestamp_ms}"}
        
        activities_processed = 0
        while True:
            try:
                response = activity_v2_service.activity().query(body=request).execute()
                activities = response.get('activities', [])
                
                for activity in activities:
                    event_type = None
                    primary_action = activity.get('primaryActionDetail', {})
                    target = activity.get('targets', [{}])[0].get('driveItem', {})
                    file_id = target.get('name', '').replace('items/', '')
                    actor = activity.get('actors', [{}])[0]
                    actor_id = actor.get('user', {}).get('knownUser', {}).get('personName', '').replace('people/', '')
                    raw_timestamp = activity.get('timestamp') or activity.get('timeRange', {}).get('endTime')
                    
                    if not raw_timestamp:
                        continue
                    
                    try:
                        if isinstance(raw_timestamp, str) and 'Z' in raw_timestamp:
                            event_dt = datetime.fromisoformat(raw_timestamp.replace('Z', '+00:00'))
                        else:
                            event_dt = datetime.fromtimestamp(int(raw_timestamp) / 1000000, tz=timezone.utc)
                        event_ts = event_dt.isoformat()
                    except (ValueError, TypeError):
                        continue
                    
                    change_id = f"activity-{file_id}-{raw_timestamp}"
                    
                    if 'create' in primary_action:
                        if 'copy' in primary_action['create']:
                            event_type = "file_copied"
                        else:
                            event_type = "file_created"
                    elif 'edit' in primary_action:
                        event_type = "file_modified"
                    elif 'delete' in primary_action:
                        event_type = "file_trashed"
                    elif 'rename' in primary_action:
                        event_type = "file_renamed"
                    elif 'move' in primary_action:
                        event_type = "file_moved"
                    elif 'permissionChange' in primary_action:
                        event_type = "file_shared_externally"
                    
                    if event_type and file_id:
                        try:
                            fields = "id, name, mimeType, createdTime, modifiedTime, trashed, parents, lastModifyingUser, md5Checksum, permissions"
                            file_metadata = drive_v3_service.files().get(fileId=file_id, fields=fields).execute()
                            permissions = file_metadata.get('permissions', [])
                            is_shared_now = is_externally_shared(permissions, user_email)
                            is_public_now = is_publicly_shared(permissions)
                            
                            if actor_id:
                                dao.save_user(cursor, {'permissionId': actor_id, 'displayName': 'Unknown (from Activity API)', 'emailAddress': None})
                            
                            dao.save_file(cursor, file_metadata, is_shared_now, is_public_now)
                            dao.save_event(cursor, change_id, file_id, event_type, actor_id, event_ts, json.dumps(file_metadata))
                            print(f"  - [Activity API] Stored Event: '{event_type}' for '{file_metadata.get('name')}'")
                            activities_processed += 1
                        except HttpError as e:
                            if e.resp.status == 404:
                                event_type = "file_deleted_permanently"
                                dao.save_event(cursor, change_id, file_id, event_type, actor_id, event_ts, '{}')
                                print(f"  - [Activity API] Stored Event: '{event_type}' for file {file_id}")
                            else:
                                print(f"  - Could not process file {file_id}: {e}")
                
                request['pageToken'] = response.get('nextPageToken')
                if not request['pageToken']:
                    break
            except HttpError as error:
                print(f"\n[ERROR] Activity API error: {error.content}")
                break
        
        if activities_processed == 0:
            print("No new activities found.")
        else:
            print(f"Processed {activities_processed} new activities.")
        
        # Update checkpoint
        dao.set_meta_value(cursor, "last_activity_timestamp", datetime.now(timezone.utc).isoformat())
        conn.commit()

        print("\n[Phase 2] Querying Changes API for moves/renames...")
        page_token = dao.get_meta_value(cursor, 'startPageToken')
        if not page_token:
            response = drive_v3_service.changes().getStartPageToken().execute()
            page_token = response.get('startPageToken')
        
        changes_processed = 0
        while page_token is not None:
            response = drive_v3_service.changes().list(
                pageToken=page_token,
                spaces='drive',
                fields='nextPageToken, newStartPageToken, changes(fileId, time)'
            ).execute()
            
            changes = response.get('changes', [])
            for change in changes:
                file_id = change.get('fileId')
                change_time = change.get('time')
                change_id = f"v3change-{file_id}-{change_time}"
                
                try:
                    fields = "id, name, mimeType, modifiedTime, trashed, parents"
                    file_metadata = drive_v3_service.files().get(fileId=file_id, fields=fields).execute()
                    event_type = None
                    previous_details = dao.get_file_details(cursor, file_id)
                    
                    if previous_details:
                        if json.dumps(file_metadata.get('parents', [])) != previous_details['parents_json']:
                            event_type = "file_moved"
                        elif file_metadata.get('name') != previous_details['name']:
                            event_type = "file_renamed"
                        
                        if event_type:
                            full_meta = drive_v3_service.files().get(fileId=file_id, fields="*").execute()
                            actor = full_meta.get('lastModifyingUser')
                            actor_id = actor.get('permissionId') if actor else None
                            permissions = full_meta.get('permissions', [])
                            is_shared = is_externally_shared(permissions, user_email)
                            is_public = is_publicly_shared(permissions)
                            
                            dao.save_file(cursor, full_meta, is_shared, is_public)
                            dao.save_event(cursor, change_id, file_id, event_type, actor_id, change_time, json.dumps(full_meta))
                            changes_processed += 1
                            print(f"  - [Changes API] Stored Fallback Event: '{event_type}' for '{full_meta.get('name')}'")
                except HttpError:
                    pass
            
            new_start_page_token = response.get('newStartPageToken')
            if new_start_page_token:
                dao.set_meta_value(cursor, "startPageToken", new_start_page_token)
            conn.commit()
            
            page_token = response.get('nextPageToken')
            if not page_token:
                break
        
        if changes_processed == 0:
            print("No fallback moves/renames found.")

    print("\n--- Data Ingestion Complete ---")

def scan_all_files(creds: Credentials):
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
            if not files:
                break
            
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
            if page_token is None:
                break
        
        conn.commit()
    
    print(f"--- Full Drive Scan Complete. Cataloged a total of {file_count} files. ---")