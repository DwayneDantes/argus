# app/analysis/contextual_risk.py (Upgraded with Burst Activity Detection)

from datetime import datetime, timedelta
from app.db import dao # Make sure dao is imported

def calculate_contextual_risk_score(cursor, event: dict) -> tuple[float, list[str]]:
    """
    Calculates the Contextual Risk (CR) score, now including checks for
    high-velocity "burst" activity.
    """
    score = 0.0
    reasons = []
    
    event_type = event.get('event_type')
    file_id = event.get('file_id')
    file_name = event.get('name', '')
    actor_id = event.get('actor_user_id')
    event_ts_str = event.get('ts')

    # --- Modifier 1: Dormant File Activation ---
    # (This logic is unchanged)
    if file_id and event_type in ['file_modified', 'file_shared_externally', 'file_trashed']:
        created_time_str = event.get('created_time')
        modified_time_str = event.get('modified_time')
        if created_time_str and modified_time_str:
            now = datetime.now()
            created_dt = datetime.fromisoformat(created_time_str.replace('Z', ''))
            last_modified_dt = datetime.fromisoformat(modified_time_str.replace('Z', ''))
            is_old_file = (now - created_dt) > timedelta(days=365)
            is_dormant = (now - last_modified_dt) > timedelta(days=180)
            if is_old_file and is_dormant:
                score += 7.0
                reasons.append("CR: Action on an old, dormant file")

    # --- Modifier 2: Suspicious Bundling ---
    # (This logic is unchanged)
    if event_type in ['file_created', 'file_copied', 'file_shared_externally']:
        if any(file_name.lower().endswith(ext) for ext in ['.zip', '.rar', '.7z']):
            score += 4.0
            reasons.append("CR: Event involves a compressed archive file")

    # --- ADDED: Modifier 3: Burst Activity Detection ---
    if actor_id and event_ts_str:
        # Use our new DAO function to count all events in the last 10 minutes.
        activity_count = dao.count_recent_user_activity(cursor, actor_id, event_ts_str)
        
        # Define a simple threshold for what constitutes a "burst".
        # A more advanced version would use a statistical baseline (e.g., z-score).
        # For now, we'll say more than 15 actions in 10 minutes is suspicious.
        if activity_count > 15:
            score += 8.0 # Add a significant risk value
            reasons.append(f"CR: Part of a high-velocity burst of activity ({activity_count} actions in 10 mins)")
    
    return score, reasons