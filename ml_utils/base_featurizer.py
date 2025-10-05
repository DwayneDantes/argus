# ml_utils/base_featurizer.py (NEW FILE)

import json
from datetime import datetime

# Define the full set of event types we know about. This is the canonical list.
EVENT_TYPE_COLUMNS = [
    'file_created', 'file_copied', 'file_renamed', 'file_moved',
    'file_modified', 'file_trashed', 'file_deleted_permanently',
    'file_shared_externally', 'permission_changed', 'file_downloaded',
    'file_opened', 'comment_added', 'folder_created'
]

def featurize_event(event: dict, baseline: dict, file_details: dict) -> list[float]:
    """
    Translates a raw event dictionary into a stateless numerical feature vector.
    This is the shared "base" featurizer for both training and live inference.
    """
    features = []

    # Handle both string and datetime objects for timestamp
    event_ts = event.get('ts') or event.get('timestamp') # Accommodate both 'ts' and 'timestamp' keys
    if isinstance(event_ts, str):
        event_dt = datetime.fromisoformat(event_ts)
    else:
        event_dt = event_ts
        
    features.append(float(event_dt.hour))
    features.append(float(event_dt.weekday()))

    is_off_hours = 0.0
    if baseline and baseline.get('typical_activity_hours_json'):
        try:
            hours = json.loads(baseline['typical_activity_hours_json'])
            start_time = datetime.strptime(hours['start'], '%H:%M').time()
            end_time = datetime.strptime(hours['end'], '%H:%M').time()
            event_time = event_dt.time()
            if start_time > end_time: # Handles overnight shifts
                if not (start_time <= event_time or event_time <= end_time):
                    is_off_hours = 1.0
            else: # Standard day shifts
                if not (start_time <= event_time <= end_time):
                    is_off_hours = 1.0
        except (json.JSONDecodeError, KeyError):
            pass
    features.append(is_off_hours)

    is_shared = 1.0 if file_details and file_details.get('is_shared_externally') else 0.0
    features.append(is_shared)
    
    vt_positives = float(file_details.get('vt_positives', 0.0)) if file_details else 0.0
    features.append(vt_positives)

    event_type = event['event_type']
    for e_type in EVENT_TYPE_COLUMNS:
        features.append(1.0 if e_type == event_type else 0.0)

    return features

def get_feature_names() -> list[str]:
    """Returns the list of stateless feature names in the correct order."""
    names = ["hour_of_day", "day_of_week", "is_off_hours", "is_shared_externally", "vt_positives"]
    names.extend([f"event_{e_type}" for e_type in EVENT_TYPE_COLUMNS])
    return names