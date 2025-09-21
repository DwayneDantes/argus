# app/analysis/contextual_risk.py (Corrected for Final Architecture)

from datetime import datetime, timedelta

def calculate_contextual_risk_score(cursor, event: dict) -> tuple[float, list[str]]:
    """
    Calculates the standalone Contextual Risk (CR) score.
    Its job is to identify contextual risk factors.
    """
    score = 0.0 # Start with zero; we only add score for specific findings.
    reasons = []
    
    event_type = event.get('event_type')
    file_id = event.get('file_id')
    file_name = event.get('name', '')

    # --- Context 1: Dormant File Activation ---
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
                # This is a significant contextual finding.
                score += 7.0
                reasons.append("CR: Action on an old, dormant file")

    # --- Context 2: Suspicious Bundling ---
    if event_type in ['file_created', 'file_copied', 'file_shared_externally']:
        if any(file_name.lower().endswith(ext) for ext in ['.zip', '.rar', '.7z']):
            score += 4.0
            reasons.append("CR: Event involves a compressed archive file")
    
    return score, reasons