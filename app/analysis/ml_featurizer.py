# app/analysis/ml_featurizer.py

import json
from datetime import datetime

# Define the full set of event types we know about. The order matters and must be consistent.
EVENT_TYPE_COLUMNS = [
    'file_created', 'file_copied', 'file_renamed', 'file_moved',
    'file_modified', 'file_trashed', 'file_deleted_permanently',
    'file_shared_externally', 'permission_change_internal'
]

def featurize_event(event: dict, baseline: dict, file_details: dict) -> list[float]:
    """
    Translates a raw event dictionary into a numerical feature vector for the ML model.
    """
    features = []

    # --- Feature 1 & 2: Timing Signals ---
    event_dt = datetime.fromisoformat(event['ts'])
    # Hour of the day (0-23)
    features.append(float(event_dt.hour))
    # Day of the week (0=Monday, 6=Sunday)
    features.append(float(event_dt.weekday()))

    # --- Feature 3: Is it "Off-Hours"? (Binary) ---
    is_off_hours = 0.0
    if baseline and baseline.get('typical_activity_hours_json'):
        try:
            hours = json.loads(baseline['typical_activity_hours_json'])
            start_time = datetime.strptime(hours['start'], '%H:%M').time()
            end_time = datetime.strptime(hours['end'], '%H:%M').time()
            if not (start_time <= event_dt.time() <= end_time):
                is_off_hours = 1.0
        except (json.JSONDecodeError, KeyError):
            pass # Default to 0.0 if baseline is malformed
    features.append(is_off_hours)

    # --- Feature 4: Is it Shared Externally? (Binary) ---
    is_shared = 0.0
    if file_details and file_details.get('is_shared_externally'):
        is_shared = 1.0
    features.append(is_shared)
    
    # --- Feature 5: Known Malware Detections (Numerical) ---
    vt_positives = 0.0
    if file_details and file_details.get('vt_positives'):
        vt_positives = float(file_details['vt_positives'])
    features.append(vt_positives)

    # --- Features 6+: Event Type (One-Hot Encoded) ---
    # This creates a binary flag for each possible event type.
    # For a 'file_trashed' event, the vector would look like: [..., 0, 0, 0, 0, 0, 1, 0, 0, 0]
    event_type = event['event_type']
    for e_type in EVENT_TYPE_COLUMNS:
        features.append(1.0 if e_type == event_type else 0.0)

    return features

def get_feature_names() -> list[str]:
    """Returns the list of feature names in the correct order."""
    names = [
        "hour_of_day",
        "day_of_week",
        "is_off_hours",
        "is_shared_externally",
        "vt_positives"
    ]
    # Add the one-hot encoded event type names
    names.extend([f"event_{e_type}" for e_type in EVENT_TYPE_COLUMNS])
    return names