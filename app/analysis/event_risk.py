# app/analysis/event_risk.py (Final Refined Version)

import json
from datetime import datetime
from app.db import dao

# These scores now represent the "Base Threat" of a single event property.
EVENT_PROPERTY_SCORES = {
    "KNOWN_MALWARE": 25.0,
    "PUBLIC_EXPOSURE": 20.0,
    "SUSPICIOUS_EXTENSION": 15.0,
    "MIME_MISMATCH": 10.0,
}

BASE_SCORES = {
    'file_created': 1, 'file_copied': 2, 'file_renamed': 1, 'file_moved': 1,
    'file_modified': 2, 'file_trashed': 5, 'file_deleted_permanently': 10,
    'file_shared_externally': 8, 'file_made_public': EVENT_PROPERTY_SCORES["PUBLIC_EXPOSURE"],
    'permission_change_internal': 1
}

SUSPICIOUS_EXTENSIONS = {'.exe', '.vbs', '.scr', '.bat', '.ps1', '.js', '.msi'}
SAFE_EXTENSION_MIME_MAP = {'.pdf': 'application/pdf', '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png', '.gif': 'image/gif', '.mp4': 'video/mp4', '.mp3': 'audio/mpeg'}

def calculate_event_risk_score(cursor, event: dict) -> tuple[float, list[str]]:
    """
    Calculates a more robust Event Risk (ER) score by identifying the single
    highest-risk property and then applying contextual multipliers.
    """
    event_type = event.get('event_type')
    actor_id = event.get('actor_user_id')
    file_id = event.get('file_id')
    event_ts_str = event.get('ts')
    reasons = []

    # --- Step 1: Identify the Highest-Risk Property of the Event ---
    base_event_threat = float(BASE_SCORES.get(event_type, 0))
    reasons.append(f"Base score for '{event_type}'")

    if event_type in ['file_created', 'file_copied']:
        vt_score = dao.get_file_vt_score(cursor, file_id)
        if vt_score is not None and vt_score > 0:
            base_event_threat = max(base_event_threat, EVENT_PROPERTY_SCORES["KNOWN_MALWARE"])
            reasons.append(f"ER: File is a known threat on VirusTotal ({vt_score} detections)")
        
        file_name = event.get('name', '').lower()
        mime_type = event.get('mime_type', '')
        file_ext = '.' + file_name.rsplit('.', 1)[1] if '.' in file_name else None

        if file_ext:
            if file_ext in SUSPICIOUS_EXTENSIONS:
                base_event_threat = max(base_event_threat, EVENT_PROPERTY_SCORES["SUSPICIOUS_EXTENSION"])
                reasons.append(f"ER: High-risk file extension ('{file_ext}') detected")
            if file_ext in SAFE_EXTENSION_MIME_MAP and SAFE_EXTENSION_MIME_MAP[file_ext] != mime_type:
                base_event_threat = max(base_event_threat, EVENT_PROPERTY_SCORES["MIME_MISMATCH"])
                reasons.append(f"ER: File extension '{file_ext}' mismatches true type ('{mime_type}')")

    # The final ER score starts as the highest single identified threat
    score = base_event_threat

    # --- Step 2: Apply Amplifiers to the Base Event Threat ---
    if not all([actor_id, file_id, event_ts_str]):
        return score, reasons

    baseline = dao.get_user_baseline(cursor, actor_id)
    if baseline and baseline['typical_activity_hours_json']:
        try:
            hours = json.loads(baseline['typical_activity_hours_json'])
            start_time = datetime.strptime(hours['start'], '%H:%M').time()
            end_time = datetime.strptime(hours['end'], '%H:%M').time()
            if not (start_time <= datetime.fromisoformat(event_ts_str).time() <= end_time):
                score *= 1.5 # Apply Off-Hours as a multiplier
                reasons.append("ER: Activity occurred outside of typical hours")
        except (json.JSONDecodeError, KeyError):
            pass
    
    return score, reasons