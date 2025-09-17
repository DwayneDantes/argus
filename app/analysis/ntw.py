# app/analysis/ntw.py (Corrected and Complete)

import sqlite3
import json
from datetime import datetime
from collections import Counter

# Import our DAO functions
from app.db.dao import (
    get_db_connection, get_user_baseline, update_user_baseline, 
    count_recent_deletions, get_file_vt_score
)

# The base scores remain the same
BASE_SCORES = {
    'file_created': 1, 'file_copied': 2, 'file_renamed': 1,
    'file_moved': 1, 'file_modified': 2, 'file_trashed': 5,
    'file_deleted_permanently': 10,
    'file_shared_externally': 8, # Reduced to a moderate-risk base score
    'permission_change_internal': 1
}


# --- The "Learning" Function (Unchanged) ---
def update_baseline():
    """
    Analyzes the entire event history for all users and calculates their
    behavioral baselines, storing the results in the user_baseline table.
    """
    print("\n--- Starting Behavioral Baseline Calculation ---")
    
    with get_db_connection() as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT DISTINCT actor_user_id FROM events WHERE actor_user_id IS NOT NULL")
        users = cursor.fetchall()
        
        if not users:
            print("No user activity found. Cannot calculate baseline.")
            return

        for user in users:
            user_id = user['actor_user_id']
            print(f"Calculating baseline for user: {user_id}...")

            cursor.execute("SELECT ts FROM events WHERE actor_user_id = ?", (user_id,))
            timestamps = cursor.fetchall()
            hours = [datetime.fromisoformat(ts['ts']).hour for ts in timestamps]
            
            if hours:
                peak_hour = Counter(hours).most_common(1)[0][0]
                start_hour = max(0, peak_hour - 4)
                end_hour = min(23, peak_hour + 5)
                typical_hours_json = json.dumps({'start': f"{start_hour:02d}:00", 'end': f"{end_hour:02d}:00"})
            else:
                typical_hours_json = None

            cursor.execute("""
                SELECT DATE(ts) as day, COUNT(*) as daily_deletions
                FROM events
                WHERE actor_user_id = ? AND (event_type = 'file_trashed' OR event_type = 'file_deleted_permanently')
                GROUP BY day
            """, (user_id,))
            deletions_by_day = cursor.fetchall()

            if deletions_by_day:
                daily_counts = [row['daily_deletions'] for row in deletions_by_day]
                avg_daily_deletions = sum(daily_counts) / len(daily_counts)
                max_historical_deletions = max(daily_counts)
                has_performed_mass_cleanup = 1 if max_historical_deletions > 100 else 0
            else:
                avg_daily_deletions = 0
                max_historical_deletions = 0
                has_performed_mass_cleanup = 0

            baseline_data = {
                'user_id': user_id,
                'typical_activity_hours_json': typical_hours_json,
                'avg_daily_deletions': avg_daily_deletions,
                'max_historical_deletions': max_historical_deletions,
                'has_performed_mass_cleanup': has_performed_mass_cleanup,
                'last_updated_ts': datetime.now().isoformat()
            }
            
            update_user_baseline(cursor, user_id, baseline_data)
            print(f"  > Baseline for user {user_id} saved successfully.")
        
        conn.commit()
    
    print("--- Baseline Calculation Complete ---")


# --- The "Thinking" Function (Enhanced) ---
def calculate_threat_score(cursor: sqlite3.Cursor, event: sqlite3.Row) -> tuple[float, list[str]]:
    """
    Calculates the threat score for an event, including all multipliers:
    Off-Hours, Mass Deletion, and Known Threat (VirusTotal).
    """
    event_type = event['event_type']
    actor_id = event['actor_user_id']
    file_id = event['file_id']
    event_ts_str = event['ts']
    reasons = []

    # 1. Get the base score.
    score = float(BASE_SCORES.get(event_type, 0))
    if score > 0:
        reasons.append(f"Base score for '{event_type}'")

    if not actor_id or score == 0:
        return score, reasons

    # 2. Get the user's learned baseline.
    baseline = get_user_baseline(cursor, actor_id)
    if not baseline:
        return score, reasons

    # --- Multiplier Section ---

    # Multiplier 1: Activity outside of normal hours.
    if baseline['typical_activity_hours_json']:
        # ... (this logic is unchanged) ...
        try:
            hours = json.loads(baseline['typical_activity_hours_json'])
            start_time = datetime.strptime(hours['start'], '%H:%M').time()
            end_time = datetime.strptime(hours['end'], '%H:%M').time()
            event_time = datetime.fromisoformat(event_ts_str).time()
            if not (start_time <= event_time <= end_time):
                score *= 1.5
                reasons.append("Multiplier: Activity occurred outside of typical hours")
        except (json.JSONDecodeError, KeyError):
            pass

    # Multiplier 2: Mass Deletion Event.
    if event_type in ['file_trashed', 'file_deleted_permanently']:
        # ... (this logic is unchanged) ...
        recent_deletion_count = count_recent_deletions(cursor, actor_id, event_ts_str)
        max_deletions_baseline = baseline['max_historical_deletions']
        if recent_deletion_count > 20 or (recent_deletion_count > max_deletions_baseline * 2 and recent_deletion_count > 5):
            score *= 3.0
            reasons.append(f"Multiplier: Part of a mass deletion event ({recent_deletion_count} deletions in last hour)")

    # --- ADDED: Multiplier 3: Known Threat via VirusTotal ---
    if event_type in ['file_created', 'file_copied']:
        # Use our new DAO function to check the local scan results. This is very fast.
        vt_score = get_file_vt_score(cursor, file_id)
        if vt_score is not None and vt_score > 0:
            # This is a confirmed malicious file. Apply a massive multiplier.
            score *= 10.0
            reasons.append(f"CRITICAL Multiplier: File is a known threat on VirusTotal ({vt_score} detections)")
    
    return score, reasons


# --- The Test Harness Function ---
def test_scoring():
    """
    Fetches the 5 most recent events from the database and runs them through
    the scoring engine to display a detailed analysis.
    """
    print("\n--- Running Threat Score Analysis on Recent Events ---")
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT e.*, f.name as file_name FROM events e
            LEFT JOIN files f ON e.file_id = f.id
            WHERE e.actor_user_id IS NOT NULL
            ORDER BY e.ts DESC
            LIMIT 5
        """)
        recent_events = cursor.fetchall()

        if not recent_events:
            print("No recent user events found to analyze.")
            return

        for event in recent_events:
            score, reasons = calculate_threat_score(cursor, event)
            
            print("\n--------------------------------------------------")
            print(f"Analyzing Event: '{event['event_type']}' on file '{event['file_name']}'")
            print(f"Timestamp: {event['ts']}")
            print(f"Final Threat Score: {score:.2f}")
            print("  Calculation Breakdown:")
            for reason in reasons:
                print(f"    - {reason}")
    print("--------------------------------------------------")