# app/analysis/contextual_risk.py (Upgraded with Burst Activity Detection)

from datetime import datetime, timedelta
from app.db import dao # Make sure dao is imported
from app import config

def calculate_contextual_risk_score(cursor, event: dict) -> tuple[float, list[str], list[str]]:
    """
    Calculates the Contextual Risk (CR) score and returns structured tags for logic.
    """
    score = 0.0
    reasons = []
    tags = []
    
    # ... (variable setup is the same) ...
    event_type = event.get('event_type'); file_id = event.get('file_id'); file_name = event.get('name', ''); actor_id = event.get('actor_user_id'); event_ts_str = event.get('ts')

    if file_id and event_type in ['file_modified', 'file_shared_externally', 'file_trashed']:
        # ... (dormant file logic is the same) ...
        created_time_str = event.get('created_time'); modified_time_str = event.get('modified_time')
        if created_time_str and modified_time_str:
            now = datetime.now(); created_dt = datetime.fromisoformat(created_time_str.replace('Z', '')); last_modified_dt = datetime.fromisoformat(modified_time_str.replace('Z', '')); is_old_file = (now - created_dt) > timedelta(days=365); is_dormant = (now - last_modified_dt) > timedelta(days=180)
            if is_old_file and is_dormant:
                # --- Use constant from the config file ---
                score += config.CONTEXTUAL_RISK_ADDITIONS["DORMANT_FILE"]
                reasons.append("CR: Action on an old, dormant file")
                tags.append("DORMANT_FILE_ACTIVATION")

    if event_type in ['file_created', 'file_copied', 'file_shared_externally']:
        if any(file_name.lower().endswith(ext) for ext in ['.zip', '.rar', '.7z']):
            # --- Use constant from the config file ---
            score += config.CONTEXTUAL_RISK_ADDITIONS["COMPRESSED_ARCHIVE"]
            reasons.append("CR: Event involves a compressed archive file")
            tags.append("COMPRESSED_ARCHIVE")

    if actor_id and event_ts_str:
        activity_count = dao.count_recent_user_activity(cursor, actor_id, event_ts_str)
        # --- Use constant from the config file ---
        if activity_count > config.BURST_ACTIVITY_THRESHOLD:
            # --- Use constant from the config file ---
            score += config.CONTEXTUAL_RISK_ADDITIONS["BURST_ACTIVITY"]
            reasons.append(f"CR: Part of a high-velocity burst of activity ({activity_count} actions in 10 mins)")
            tags.append("BURST_ACTIVITY")
    
    return score, reasons, tags