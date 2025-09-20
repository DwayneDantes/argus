# app/analysis/contextual_risk.py (Corrected and Complete)

from datetime import datetime, timedelta

def calculate_contextual_risk_score(cursor, event: dict, initial_er_score: float) -> tuple[float, list[str]]:
    """
    Calculates the Contextual Risk (CR) by applying multipliers to the initial
    Event Risk score.
    """
    final_cr_score = initial_er_score
    reasons = []
    
    event_type = event.get('event_type')
    file_id = event.get('file_id')

    if not file_id or event_type not in ['file_modified', 'file_shared_externally', 'file_trashed']:
        return 0.0, []

    cursor.execute("SELECT created_time, modified_time FROM files WHERE id = ?", (file_id,))
    file_times = cursor.fetchone()

    if not file_times:
        return 0.0, []

    now = datetime.now()
    created_dt = datetime.fromisoformat(file_times['created_time'])
    last_modified_dt = datetime.fromisoformat(file_times['modified_time'])

    is_old_file = (now - created_dt) > timedelta(days=365)
    is_dormant = (now - last_modified_dt) > timedelta(days=180)

    if is_old_file and is_dormant:
        final_cr_score *= 2.0
        reasons.append("CR Multiplier: Action on a dormant file")

    contextual_risk_added = final_cr_score - initial_er_score
    
    return contextual_risk_added, reasons