# app/analysis/contextual_risk.py (FINAL, CORRECTED, AND ROBUST)

import logging
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

# In-memory state store: actor_id -> deque of recent event dictionaries
ACTOR_WINDOWS = defaultdict(deque)

# Max window size to prevent memory leaks
MAX_WINDOW_MINUTES = 45

# --- Thresholds for defining discrete micro-patterns ---
# This makes the logic clear and easy to tune
BULK_COPY_THRESHOLD = 2

def update_and_compute_micro_patterns(event: dict) -> dict:
    """
    Computes both historical ML features and discrete narrative micro-patterns.
    It first computes all features based on the actor's history, then updates
    the history with the current event.
    """
    actor_id = event.get('actor_user_id')
    if not actor_id:
        return {}

    event_ts = event.get('ts')
    if not isinstance(event_ts, datetime):
        event_ts = datetime.fromisoformat(str(event_ts).replace('Z', '+00:00'))

    window = ACTOR_WINDOWS[actor_id]

    # --- Step 1: Compute HISTORICAL Features for ML Model (as before) ---
    features = {}
    
    if window:
        last_event_ts = window[-1].get('ts')
        if not isinstance(last_event_ts, datetime):
            last_event_ts = datetime.fromisoformat(str(last_event_ts).replace('Z', '+00:00'))
        features['time_since_last_event_for_actor'] = (event_ts - last_event_ts).total_seconds()
    else:
        features['time_since_last_event_for_actor'] = 0.0

    thirty_min_ago = event_ts - timedelta(minutes=30)
    fifteen_min_ago = event_ts - timedelta(minutes=15)
    ten_min_ago = event_ts - timedelta(minutes=10)

    events_30m = [e for e in window if (e.get('ts') if isinstance(e.get('ts'), datetime) else datetime.fromisoformat(str(e.get('ts')))) >= thirty_min_ago]
    events_15m = [e for e in events_30m if (e.get('ts') if isinstance(e.get('ts'), datetime) else datetime.fromisoformat(str(e.get('ts')))) >= fifteen_min_ago]
    events_10m = [e for e in events_15m if (e.get('ts') if isinstance(e.get('ts'), datetime) else datetime.fromisoformat(str(e.get('ts')))) >= ten_min_ago]

    features['actor_copy_count_30m'] = float(sum(1 for e in events_30m if e['event_type'] == 'file_copied'))
    features['actor_trash_count_30m'] = float(sum(1 for e in events_30m if e['event_type'] == 'file_trashed'))
    features['actor_download_count_30m'] = float(sum(1 for e in events_30m if e.get('event_type') == 'file_downloaded'))
    features['actor_external_share_count_15m'] = float(sum(1 for e in events_15m if e['event_type'] == 'file_shared_externally'))
    
    archive_created_flag = any(e['event_type'] == 'file_created' and e.get('mime_type') == 'application/zip' for e in events_10m)
    features['actor_archive_created_flag_10m'] = 1.0 if archive_created_flag else 0.0

    # --- Step 2: >>> FIX IS HERE <<< ---
    # Detect DISCRETE Micro-Patterns from the CURRENT Event for the Narrative Builder
    event_type = event.get('event_type')
    mime_type = event.get('mime_type')

    # Detect 'bulk_copy'
    # This pattern triggers when the number of copies *crosses* the threshold.
    if event_type == 'file_copied':
        # The ML feature 'actor_copy_count_30m' is the count *before* this event.
        # So, if the previous count was N-1 and this event makes it N, the pattern fires.
        if (features['actor_copy_count_30m'] + 1) == BULK_COPY_THRESHOLD:
            features['bulk_copy'] = {
                'count': BULK_COPY_THRESHOLD,
                'time_window_minutes': 30
            }

    # Detect 'archive_create'
    if event_type == 'file_created' and mime_type == 'application/zip':
        features['archive_create'] = {
            'filename': event.get('name'),
            'timestamp': event.get('ts').isoformat()
        }

    # Detect 'external_share'
    if event_type == 'file_shared_externally':
        features['external_share'] = {
            'filename': event.get('name'),
            'timestamp': event.get('ts').isoformat()
        }

    # --- Step 3: Update the Actor's Event Window for the NEXT event (as before) ---
    window.append(event)
    while window:
        oldest_event_ts = window[0].get('ts')
        if not isinstance(oldest_event_ts, datetime):
            oldest_event_ts = datetime.fromisoformat(str(oldest_event_ts).replace('Z', '+00:00'))
            
        if (event_ts - oldest_event_ts) > timedelta(minutes=MAX_WINDOW_MINUTES):
            window.popleft()
        else:
            break

    return features