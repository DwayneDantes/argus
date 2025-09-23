# app/analysis/narrative_builder.py (Refactored for Scoring)

from datetime import datetime, timedelta
from app.db import dao
import re
# We no longer use the old scoring function here
# from app.analysis.ntw import calculate_threat_score 

# --- A Note on Narrative Scoring ---
# Narratives are high-impact by nature. If one is detected, we assign a high, fixed score.
# This score can be augmented by the individual Event Risk scores of its component events.
NARRATIVE_BASE_SCORES = {
    'data_exfiltration': 15.0,
    'mass_deletion': 20.0,
    # --- ADDED: The new high-impact narrative ---
    'ransomware_footprint': 25.0 # Assign a very high base score
}

def analyze_narratives_for_file(cursor, file_id: str) -> tuple[float, list[str]]:
    """
    Analyzes a single file's history for all known narratives.
    Returns the total narrative score and a list of detected narratives.
    """
    total_score = 0.0
    detected_narratives = []

    # --- Detective 1: Data Exfiltration ---
    cursor.execute("SELECT event_type FROM events WHERE file_id = ?", (file_id,))
    event_history = [row['event_type'] for row in cursor.fetchall()]

    is_copied = 'file_copied' in event_history
    is_renamed = 'file_renamed' in event_history
    is_shared = 'file_shared_externally' in event_history

    if is_copied and is_renamed and is_shared:
        total_score += NARRATIVE_BASE_SCORES['data_exfiltration']
        detected_narratives.append("NR: Data Exfiltration by Obfuscation")

    # --- (Future detectives for other narratives would go here) ---
    
    return total_score, detected_narratives


def analyze_mass_deletion_for_user(cursor, user_id: str) -> tuple[float, list[str]]:
    """
    Analyzes a user's entire history for "bursts" of deletion activity that
    are abnormal compared to their baseline.
    """
    total_score = 0.0
    detected_narratives = []

    # First, get the user's personal baseline. We can't do anything without it.
    baseline = dao.get_user_baseline(cursor, user_id)
    if not baseline:
        return 0.0, []

    # This complex query is the core of our detection. It groups all deletion events
    # by user and by the hour they occurred, and counts them.
    cursor.execute("""
        SELECT
            COUNT(*) as deletion_count,
            MIN(ts) as first_deletion_ts,
            MAX(ts) as last_deletion_ts
        FROM events
        WHERE
            actor_user_id = ? AND
            event_type IN ('file_trashed', 'file_deleted_permanently')
        GROUP BY strftime('%Y-%m-%d %H', ts) -- Group events by the hour
        HAVING deletion_count > 5 -- Pre-filter to only analyze significant bursts
    """, (user_id,))
    
    deletion_bursts = cursor.fetchall()

    if not deletion_bursts:
        return 0.0, []

    max_deletions_baseline = baseline['max_historical_deletions']

    for burst in deletion_bursts:
        deletion_count = burst['deletion_count']
        
        # Apply our smart, adaptive logic to see if this burst is abnormal
        is_mass_deletion = (
            deletion_count > 20 or 
            (deletion_count > max_deletions_baseline * 2 and deletion_count > 5)
        )

        if is_mass_deletion:
            # We found a mass deletion narrative!
            total_score += NARRATIVE_BASE_SCORES['mass_deletion']
            
            # Create a descriptive reason for the report
            reason = (
                f"NR: Mass Deletion detected. "
                f"{deletion_count} files were deleted between {burst['first_deletion_ts']} "
                f"and {burst['last_deletion_ts']}. "
                f"(User's previous max: {max_deletions_baseline})"
            )
            detected_narratives.append(reason)

    return total_score, detected_narratives

def analyze_ransomware_footprint(cursor, user_id: str, event_ts_str: str) -> tuple[float, list[str]]:
    """
    Analyzes a 1-hour window around a given event for the specific
    pattern of a ransomware attack.
    """
    score = 0.0
    reasons = []

    # --- THIS IS THE CORRECTED LOGIC ---
    # Define a 1-hour window for the analysis based on the single event timestamp
    event_dt = datetime.fromisoformat(event_ts_str.replace('Z',''))
    start_ts = (event_dt - timedelta(minutes=30)).isoformat()
    end_ts = (event_dt + timedelta(minutes=30)).isoformat()
    
    ransomware_ext_pattern = r'\.(locked|crypted|encrypted|kraken|onion|\[\w+\])$'
    ransom_note_pattern = r'^(readme|recover|decrypt|help).*\.(txt|html)$'

    cursor.execute("""
        SELECT file_id, event_type, name FROM events e
        LEFT JOIN files f ON e.file_id = f.id
        WHERE e.actor_user_id = ? AND e.ts >= ? AND e.ts <= ?
    """, (user_id, start_ts, end_ts))
    activity_window = cursor.fetchall()

    if not activity_window:
        return 0.0, []

    modified_files = set()
    renamed_to_ransom_ext = set()
    ransom_note_found = False

    for event in activity_window:
        if event['event_type'] == 'file_modified':
            modified_files.add(event['file_id'])
        elif event['event_type'] == 'file_renamed' and event['name']:
            if re.search(ransomware_ext_pattern, event['name'], re.IGNORECASE):
                renamed_to_ransom_ext.add(event['file_id'])
        elif event['event_type'] == 'file_created' and event['name']:
            if re.search(ransom_note_pattern, event['name'], re.IGNORECASE):
                ransom_note_found = True

    points = 0
    encrypted_files_count = len(modified_files.intersection(renamed_to_ransom_ext))

    if encrypted_files_count > 5:
        points += 15
        reasons.append(f"NR: Detected {encrypted_files_count} files modified then renamed to a ransom extension.")
    if ransom_note_found:
        points += 10
        reasons.append("NR: A file matching a common ransom note name was also created.")

    if points >= 15:
        score = NARRATIVE_BASE_SCORES['ransomware_footprint']
    
    return score, reasons