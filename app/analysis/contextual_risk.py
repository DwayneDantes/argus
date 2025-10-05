# app/analysis/contextual_risk.py (FINAL, ROBUST VERSION WITH TIMEZONE HANDLING)

from datetime import datetime, timedelta, timezone 
from app.db import dao
from app import config

def _make_aware(dt_obj: datetime) -> datetime:
    """Helper function to make a datetime object timezone-aware (UTC) if it's naive."""
    if dt_obj.tzinfo is None:
        # If the datetime is naive, assign the UTC timezone to it.
        return dt_obj.replace(tzinfo=timezone.utc)
    # If it's already aware, return it as is.
    return dt_obj

def calculate_contextual_risk_score(cursor, event: dict) -> tuple[float, list[str], list[str]]:
    """
    Calculates the Contextual Risk (CR) score and returns structured tags for logic.
    """
    score = 0.0
    reasons = []
    tags = []
    
    event_type = event.get('event_type')
    file_id = event.get('file_id')
    file_name = event.get('name', '')
    actor_id = event.get('actor_user_id')
    
    # The 'ts' from the event is now a datetime object, not a string
    event_ts = event.get('ts')

    if file_id and event_type in ['file_modified', 'file_shared_externally', 'file_trashed']:
        # These timestamps from the 'files' table might be strings or None
        created_time_str = event.get('created_time')
        modified_time_str = event.get('modified_time')

        if created_time_str and modified_time_str:
            try:
                # --- THIS IS THE FIX ---
                # Get the current time in UTC
                now = datetime.now(timezone.utc)
                
                # Convert the timestamp strings from the DB into datetime objects
                created_dt_naive = datetime.fromisoformat(str(created_time_str).replace('Z', ''))
                modified_dt_naive = datetime.fromisoformat(str(modified_time_str).replace('Z', ''))

                # Use our helper to make them timezone-aware (UTC) before comparison
                created_dt_aware = _make_aware(created_dt_naive)
                modified_dt_aware = _make_aware(modified_dt_naive)

                # Now, all comparisons are between timezone-aware objects
                is_old_file = (now - created_dt_aware) > timedelta(days=365)
                is_dormant = (now - modified_dt_aware) > timedelta(days=180)
                # --- END OF FIX ---

                if is_old_file and is_dormant:
                    score += config.CONTEXTUAL_RISK_ADDITIONS["DORMANT_FILE"]
                    reasons.append("CR: Action on an old, dormant file")
                    tags.append("DORMANT_FILE_ACTIVATION")
            except (ValueError, TypeError):
                # Failsafe in case of a malformed timestamp string
                pass

    if event_type in ['file_created', 'file_copied', 'file_shared_externally']:
        if any(file_name.lower().endswith(ext) for ext in ['.zip', '.rar', '.7z']):
            score += config.CONTEXTUAL_RISK_ADDITIONS["COMPRESSED_ARCHIVE"]
            reasons.append("CR: Event involves a compressed archive file")
            tags.append("COMPRESSED_ARCHIVE")

    if actor_id and event_ts:
        # Pass the datetime object directly to the DAO function
        activity_count = dao.count_recent_user_activity(cursor, actor_id, event_ts)
        if activity_count > config.BURST_ACTIVITY_THRESHOLD:
            score += config.CONTEXTUAL_RISK_ADDITIONS["BURST_ACTIVITY"]
            reasons.append(f"CR: Part of a high-velocity burst of activity ({activity_count} actions in 10 mins)")
            tags.append("BURST_ACTIVITY")
    
    return score, reasons, tags