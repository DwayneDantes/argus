# app/analysis/narrative_builder.py (Complete and Verified)

from app.db import dao
from app.analysis.ntw import calculate_threat_score, BASE_SCORES # Corrected import
import json
from datetime import datetime

# --- NARRATIVE 1: DATA EXFILTRATION ---
def find_data_exfiltration_narratives():
    """
    Analyzes the event log to find sequences of events that match a known
    data exfiltration pattern, and scores the entire narrative contextually.
    """
    print("\n--- Searching for Data Exfiltration Narratives ---")
    
    with dao.get_db_connection() as conn:
        cursor = conn.cursor()

        cursor.execute("""
            SELECT DISTINCT e.file_id, f.name FROM events e
            JOIN files f ON e.file_id = f.id
            WHERE e.event_type = 'file_shared_externally'
        """)
        suspect_files = cursor.fetchall()

        if not suspect_files:
            print("No externally shared files found. No potential data exfiltration narratives to analyze.")
            return

        print(f"Found {len(suspect_files)} externally shared files. Analyzing their history...")
        
        for file_row in suspect_files:
            file_id = file_row['file_id']
            file_name = file_row['name']
            
            cursor.execute("SELECT * FROM events WHERE file_id = ? ORDER BY ts ASC", (file_id,))
            event_history_rows = cursor.fetchall()

            events_in_narrative = []
            found_copied = False
            found_renamed = False
            found_shared_externally = False
            narrative_total_score = 0.0
            narrative_reasons = []

            for event_row in event_history_rows:
                event_type = event_row['event_type']
                event_score, event_reasons = calculate_threat_score(cursor, event_row)
                
                if event_type == 'file_copied':
                    found_copied = True
                    events_in_narrative.append(event_row)
                    narrative_total_score += event_score
                    reasons_str = f"Copied (Score: {event_score:.2f}, Reasons: {', '.join(event_reasons)})" if event_score > BASE_SCORES.get('file_copied', 0) else f"Copied (Score: {event_score:.2f})"
                    narrative_reasons.append(reasons_str)

                elif event_type == 'file_renamed':
                    found_renamed = True
                    events_in_narrative.append(event_row)
                    narrative_total_score += event_score
                    reasons_str = f"Renamed (Score: {event_score:.2f}, Reasons: {', '.join(event_reasons)})" if event_score > BASE_SCORES.get('file_renamed', 0) else f"Renamed (Score: {event_score:.2f})"
                    narrative_reasons.append(reasons_str)

                elif event_type == 'file_shared_externally':
                    found_shared_externally = True
                    events_in_narrative.append(event_row)
                    narrative_total_score += event_score
                    reasons_str = f"Shared Externally (Score: {event_score:.2f}, Reasons: {', '.join(event_reasons)})" if event_score > BASE_SCORES.get('file_shared_externally', 0) else f"Shared Externally (Score: {event_score:.2f})"
                    narrative_reasons.append(reasons_str)

            if found_copied and found_renamed and found_shared_externally:
                print("\n" + "#"*70)
                print(f"!!! HIGH-THREAT NARRATIVE DETECTED: Potential Data Exfiltration !!!")
                print(f"  File: '{file_name}' (ID: {file_id})")
                print(f"  Overall Narrative Threat Score: {narrative_total_score:.2f}")
                print("\n  Summary: This file was copied, then renamed, and finally shared externally.")
                print("  Narrative Breakdown:")
                for reason in narrative_reasons:
                    print(f"    - {reason}")
                
                print("\n  Detailed Event Sequence:")
                for event in events_in_narrative:
                    actor_name = "Unknown"
                    if event['actor_user_id']:
                        actor_cursor = conn.cursor()
                        actor_cursor.execute("SELECT display_name FROM users WHERE id = ?", (event['actor_user_id'],))
                        actor_row = actor_cursor.fetchone()
                        if actor_row:
                            actor_name = actor_row['display_name']
                    print(f"    - {event['ts']}: {event['event_type']} by {actor_name}")
                print("#"*70)
    
    print("\n--- Data Exfiltration Narrative Search Complete ---")


# --- NARRATIVE 2: MASS DELETION ---
def find_mass_deletion_narratives():
    """
    Analyzes the event log to find "bursts" of deletion activity that are
    abnormal for a user, and flags them as a single narrative.
    """
    print("\n--- Searching for Mass Deletion Narratives ---")
    
    with dao.get_db_connection() as conn:
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                actor_user_id,
                strftime('%Y-%m-%d %H:00:00', ts) as hour_window,
                COUNT(*) as deletion_count,
                MIN(ts) as first_deletion_ts,
                MAX(ts) as last_deletion_ts
            FROM events
            WHERE event_type IN ('file_trashed', 'file_deleted_permanently')
            GROUP BY actor_user_id, hour_window
            HAVING deletion_count > 5
        """)
        deletion_bursts = cursor.fetchall()

        if not deletion_bursts:
            print("No significant deletion bursts found to analyze.")
            return

        for burst in deletion_bursts:
            user_id = burst['actor_user_id']
            deletion_count = burst['deletion_count']

            baseline = dao.get_user_baseline(cursor, user_id)
            if not baseline:
                continue

            max_deletions_baseline = baseline['max_historical_deletions']
            is_mass_deletion = (deletion_count > 20 or (deletion_count > max_deletions_baseline * 2 and deletion_count > 5))

            if is_mass_deletion:
                actor_name_cursor = conn.cursor()
                actor_name_cursor.execute("SELECT display_name FROM users WHERE id = ?", (user_id,))
                actor_row = actor_name_cursor.fetchone()
                actor_name = actor_row['display_name'] if actor_row else user_id

                print("\n" + "#"*70)
                print(f"!!! HIGH-THREAT NARRATIVE DETECTED: Mass Deletion Event !!!")
                print(f"  - Actor: {actor_name}")
                print(f"  - Time Window: Between {burst['first_deletion_ts']} and {burst['last_deletion_ts']}")
                print(f"  - Summary: {deletion_count} files were deleted in a short period.")
                print(f"  - Context: This is highly unusual for this user, whose previous maximum was {max_deletions_baseline} deletions.")
                
                files_cursor = conn.cursor()
                files_cursor.execute("""
                    SELECT f.name FROM events e
                    JOIN files f ON e.file_id = f.id
                    WHERE e.actor_user_id = ? AND e.ts >= ? AND e.ts <= ?
                    AND e.event_type IN ('file_trashed', 'file_deleted_permanently')
                    LIMIT 5
                """, (user_id, burst['first_deletion_ts'], burst['last_deletion_ts']))
                deleted_files = files_cursor.fetchall()
                if deleted_files:
                    print("  - Sample of Deleted Files:")
                    for file in deleted_files:
                        print(f"    - {file['name']}")
                print("#"*70)

    print("\n--- Mass Deletion Narrative Search Complete ---")