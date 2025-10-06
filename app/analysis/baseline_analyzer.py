# app/analysis/baseline_analyzer.py (Correct and Complete)

import json
from datetime import datetime
from collections import Counter
from app.db import dao

def update_baseline():
    """
    Analyzes the entire event history for all users and calculates their
    behavioral baselines, storing the results in the user_baseline table.
    """
    print("\n--- Starting Behavioral Baseline Calculation ---")
    
    with dao.get_db_connection() as conn:
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
            hours = [ts['ts'].hour for ts in timestamps]
            
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
            
            dao.update_user_baseline(cursor, user_id, baseline_data)
            print(f"  > Baseline for user {user_id} saved successfully.")
        
        conn.commit()
    
    print("--- Baseline Calculation Complete ---")