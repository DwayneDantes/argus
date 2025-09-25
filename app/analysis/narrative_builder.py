# app/analysis/narrative_builder.py (FINAL, USING CONFIG)

import re
from datetime import datetime, timedelta
from app.db import dao
from app import config # IMPORT THE NEW CONFIG FILE

# The old hardcoded dictionary has been removed.

# --- NARRATIVE 1 ---
def analyze_narratives_for_file(cursor, file_id: str) -> tuple[float, list[str]]:
    score = 0.0
    reasons = []
    cursor.execute("SELECT event_type FROM events WHERE file_id = ?", (file_id,))
    event_history = [row['event_type'] for row in cursor.fetchall()]
    if 'file_copied' in event_history and 'file_renamed' in event_history and 'file_shared_externally' in event_history:
        # --- Use constant from the config file ---
        score += config.NARRATIVE_BASE_SCORES['data_exfiltration']
        reasons.append("NR: Data Exfiltration by Obfuscation")
    return score, reasons

# --- NARRATIVE 2 ---
def analyze_mass_deletion_for_user(cursor, user_id: str) -> tuple[float, list[str]]:
    score = 0.0
    reasons = []
    baseline = dao.get_user_baseline(cursor, user_id)
    if not baseline: return 0.0, []
    cursor.execute("""
        SELECT COUNT(*) as deletion_count, MIN(ts) as first_ts, MAX(ts) as last_ts
        FROM events WHERE actor_user_id = ? AND event_type IN ('file_trashed', 'file_deleted_permanently')
        GROUP BY strftime('%Y-%m-%d %H', ts) HAVING deletion_count > 5
    """, (user_id,))
    bursts = cursor.fetchall()
    if not bursts: return 0.0, []
    max_baseline = baseline['max_historical_deletions']
    for burst in bursts:
        count = burst['deletion_count']
        if count > 20 or (count > max_baseline * 2 and count > 5):
            # --- Use constant from the config file ---
            score += config.NARRATIVE_BASE_SCORES['mass_deletion']
            reason = f"NR: Mass Deletion detected ({count} files deleted)."
            reasons.append(reason)
    return score, reasons

# --- NARRATIVE 3 ---
def analyze_ransomware_footprint(cursor, user_id: str, event_ts_str: str) -> tuple[float, list[str]]:
    score = 0.0
    reasons = []
    event_dt = datetime.fromisoformat(event_ts_str.replace('Z',''))
    start_ts = (event_dt - timedelta(minutes=30)).isoformat()
    end_ts = (event_dt + timedelta(minutes=30)).isoformat()
    
    pattern = r'\.(locked|crypted|encrypted|kraken|onion|\[\w+\])$'
    note_pattern = r'^(readme|recover|decrypt|help).*\.(txt|html)$'

    cursor.execute("""
        SELECT file_id, event_type, name FROM events e LEFT JOIN files f ON e.file_id = f.id
        WHERE e.actor_user_id = ? AND e.ts >= ? AND e.ts <= ?
    """, (user_id, start_ts, end_ts))
    activity = cursor.fetchall()

    if not activity: return 0.0, []

    modified = set()
    renamed = set()
    note_found = False

    for event in activity:
        if event['event_type'] == 'file_modified': modified.add(event['file_id'])
        elif event['event_type'] == 'file_renamed' and event['name']:
            if re.search(pattern, event['name'], re.IGNORECASE): renamed.add(event['file_id'])
        elif event['event_type'] == 'file_created' and event['name']:
            if re.search(note_pattern, event['name'], re.IGNORECASE): note_found = True

    points = 0
    encrypted_count = len(modified.intersection(renamed))

    if encrypted_count > 5:
        points += 15
        reasons.append(f"NR: Detected {encrypted_count} files modified then renamed to a ransom extension.")
    if note_found:
        points += 10
        reasons.append("NR: A file matching a common ransom note name was also created.")
    
    if points >= 15:
        # --- Use constant from the config file ---
        score = config.NARRATIVE_BASE_SCORES['ransomware_footprint']
    
    return score, reasons