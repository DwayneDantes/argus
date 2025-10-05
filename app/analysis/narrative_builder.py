# app/analysis/narrative_builder.py (FINAL, CORRECTED VERSION)

import re
from datetime import datetime, timedelta
from app.db import dao
from app import config

# --- NARRATIVE 1: DATA EXFILTRATION (UPGRADED LOGIC) ---
def analyze_exfiltration_by_obfuscation(event: dict, cursor) -> dict | None:
    """
    Detects a "Copy -> Rename -> Share" pattern. If found, returns a structured
    dictionary representing the narrative hit. Otherwise, returns None.
    """
    if event.get('event_type') != 'file_shared_externally':
        return None

    template = config.NARRATIVE_TEMPLATES['EXFILTRATION_V1']
    time_window = timedelta(minutes=template['time_window_minutes'])
    
    shared_file_id = event['file_id']
    sharing_actor_id = event['actor_user_id']
    
    # --- FIX: event['ts'] is now a datetime object, not a string ---
    share_time = event['ts']

    history = dao.get_file_event_history(cursor, shared_file_id)
    if not history:
        return None

    creation_event = dict(history[0])
    
    # --- FIX: creation_event['ts'] is also a datetime object ---
    creation_time = creation_event['ts']

    if (share_time - creation_time) > time_window:
        return None

    score = 0.0
    contributing_events = []
    stages_found = []
    
    if creation_event['event_type'] == 'file_copied':
        score += template['stage_weights']['copied']
        stages_found.append('copied')
        contributing_events.append({'event_id': creation_event['id'], 'stage': 'copied'})

    for history_event_row in history:
        history_event = dict(history_event_row)
        
        # --- FIX: history_event['ts'] is also a datetime object ---
        event_time = history_event['ts']
        
        if (history_event['event_type'] == 'file_renamed' and 
            history_event['actor_user_id'] == sharing_actor_id and
            creation_time < event_time < share_time):
            
            score += template['stage_weights']['renamed']
            stages_found.append('renamed')
            contributing_events.append({'event_id': history_event['id'], 'stage': 'renamed'})
            break

    score += template['stage_weights']['shared']
    stages_found.append('shared')
    contributing_events.append({'event_id': event['id'], 'stage': 'shared'})
    
    if 'copied' in stages_found and 'renamed' in stages_found:
        reason = (f"NR: High-confidence exfiltration pattern detected on file {shared_file_id} "
                  f"(Copy -> Rename -> Share sequence within {time_window}).")
        
        return {
            "narrative_type": "EXFILTRATION_V1",
            "score": score,
            "reason": reason,
            "contributing_events": contributing_events,
            "primary_actor_id": sharing_actor_id,
            "start_time": creation_time.isoformat(),
            "end_time": share_time.isoformat()
        }

    return None


# --- LEGACY NARRATIVES (Unchanged until they are upgraded) ---
# NOTE: The ransomware function is also fixed to accept a datetime object.

def analyze_mass_deletion_for_user(cursor, user_id: str) -> tuple[float, list[str]]:
    score = 0.0; reasons = []; baseline = dao.get_user_baseline(cursor, user_id)
    if not baseline: return 0.0, []
    cursor.execute("SELECT COUNT(*) as deletion_count FROM events WHERE actor_user_id = ? AND event_type IN ('file_trashed', 'file_deleted_permanently') AND ts >= datetime('now', '-1 hours')", (user_id,))
    bursts = cursor.fetchall()
    if not bursts: return 0.0, []
    max_baseline = baseline['max_historical_deletions']
    for burst in bursts:
        count = burst['deletion_count']
        if count > 20 or (count > max_baseline * 2 and count > 5):
            score += config.NARRATIVE_BASE_SCORES['mass_deletion']
            reasons.append(f"NR: Mass Deletion detected ({count} files deleted).")
    return score, reasons

def analyze_ransomware_footprint(cursor, user_id: str, event_ts: datetime) -> tuple[float, list[str]]:
    score = 0.0; reasons = []
    # --- FIX: The input is now a datetime object ---
    event_dt = event_ts
    start_ts = (event_dt - timedelta(minutes=30)).isoformat()
    end_ts = (event_dt + timedelta(minutes=30)).isoformat()
    
    pattern = r'\.(locked|crypted|encrypted|kraken|onion|\[\w+\])$'; note_pattern = r'^(readme|recover|decrypt|help).*\.(txt|html)$'
    cursor.execute("SELECT file_id, event_type, name FROM events e LEFT JOIN files f ON e.file_id = f.id WHERE e.actor_user_id = ? AND e.ts >= ? AND e.ts <= ?", (user_id, start_ts, end_ts))
    activity = cursor.fetchall()
    if not activity: return 0.0, []
    modified = set(); renamed = set(); note_found = False
    for event in activity:
        if event['event_type'] == 'file_modified': modified.add(event['file_id'])
        elif event['event_type'] == 'file_renamed' and event['name']:
            if re.search(pattern, event['name'], re.IGNORECASE): renamed.add(event['file_id'])
        elif event['event_type'] == 'file_created' and event['name']:
            if re.search(note_pattern, event['name'], re.IGNORECASE): note_found = True
    points = 0; encrypted_count = len(modified.intersection(renamed))
    if encrypted_count > 5:
        points += 15; reasons.append(f"NR: Detected {encrypted_count} files modified then renamed to a ransom extension.")
    if note_found:
        points += 10; reasons.append("NR: A file matching a common ransom note name was also created.")
    if points >= 15: score = config.NARRATIVE_BASE_SCORES['ransomware_footprint']
    return score, reasons