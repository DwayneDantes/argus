# app/analysis/event_risk.py

import json
from datetime import datetime
from app.db import dao

# These base scores are now the foundation of Event Risk
BASE_SCORES = {
    'file_created': 1, 'file_copied': 2, 'file_renamed': 1,
    'file_moved': 1, 'file_modified': 2, 'file_trashed': 5,
    'file_deleted_permanently': 10,
    'file_shared_externally': 8,
    'permission_change_internal': 1,
     'file_made_public': 20
}

# In app/analysis/event_risk.py
# REPLACE the existing function with this one

def calculate_event_risk_score(cursor, event: dict) -> tuple[float, list[str]]:
    """
    Calculates the Event Risk (ER) score for a single event.
    """
    event_type = event.get('event_type')
    actor_id = event.get('actor_user_id')
    file_id = event.get('file_id')
    event_ts_str = event.get('ts')
    reasons = []

    score = float(BASE_SCORES.get(event_type, 0))
    if score > 0:
        reasons.append(f"Base score for '{event_type}'")

    if not actor_id or score == 0 or not file_id or not event_ts_str:
        return score, reasons

    # --- ADDED: Robustness Check ---
    baseline = dao.get_user_baseline(cursor, actor_id)
    # If no baseline exists for this user yet, we cannot check for off-hours.
    # We gracefully skip this part of the analysis.
    if baseline and baseline['typical_activity_hours_json']:
        try:
            hours = json.loads(baseline['typical_activity_hours_json'])
            start_time = datetime.strptime(hours['start'], '%H:%M').time()
            end_time = datetime.strptime(hours['end'], '%H:%M').time()
            event_time = datetime.fromisoformat(event_ts_str).time()
            if not (start_time <= event_time <= end_time):
                score *= 1.5
                reasons.append("ER: Activity occurred outside of typical hours")
        except (json.JSONDecodeError, KeyError):
            pass

    if event_type in ['file_created', 'file_copied']:
        vt_score = dao.get_file_vt_score(cursor, file_id)
        # This check is already robust (vt_score is not None)
        if vt_score is not None and vt_score > 0:
            score *= 10.0
            reasons.append(f"ER: File is a known threat on VirusTotal ({vt_score} detections)")
    
    return score, reasons