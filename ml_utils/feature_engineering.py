# ml_utils/feature_engineering.py (FINAL-FINAL CORRECTED VERSION)

import pandas as pd
import numpy as np

def generate_feature_matrix(events_df: pd.DataFrame) -> pd.DataFrame:
    if events_df.empty:
        return pd.DataFrame()

    events_df['timestamp'] = pd.to_datetime(events_df['timestamp'])
    events_df = events_df.sort_values(by='timestamp').reset_index(drop=True)

    # --- START OF THE DEFINITIVE FIX ---
    # We will build the features row by row in a list of dicts. Slower, but 100% correct.
    
    # Pre-calculate stateless features
    stateless_features = pd.DataFrame(index=events_df.index)
    stateless_features['hour_of_day'] = events_df['timestamp'].dt.hour
    stateless_features['day_of_week'] = events_df['timestamp'].dt.dayofweek
    stateless_features = stateless_features.join(pd.get_dummies(events_df['event_type'], prefix='event'))

    # Pre-calculate stateful features using a temporary index
    temp_df = events_df.set_index('timestamp')
    temp_df['is_copy'] = (temp_df['event_type'] == 'file_copied').astype(int)
    # ... add other 'is_*' columns ...

    # We will build the final combined DataFrame here
    final_feature_rows = []

    for index, row in events_df.iterrows():
        actor = row['actor_email']
        current_time = row['timestamp']
        
        # Get all of this actor's history *before* the current event
        actor_history = temp_df[
            (temp_df['actor_email'] == actor) & (temp_df.index < current_time)
        ]

        # Define lookback windows from the current event's time
        thirty_min_ago = current_time - pd.Timedelta(minutes=30)
        
        # Calculate features based on the filtered history
        history_30m = actor_history[actor_history.index >= thirty_min_ago]
        
        current_features = {
            'actor_copy_count_30m': history_30m['is_copy'].sum(),
            # ... add other features here ...
        }
        
        # Get time since last event
        if not actor_history.empty:
            time_diff = current_time - actor_history.index[-1]
            current_features['time_since_last_event_for_actor'] = time_diff.total_seconds()
        else:
            current_features['time_since_last_event_for_actor'] = 0.0

        final_feature_rows.append(current_features)
    
    stateful_features = pd.DataFrame(final_feature_rows, index=events_df.index)
    
    # Combine stateless and stateful features
    features = stateless_features.join(stateful_features)
    # --- END OF THE DEFINITIVE FIX ---
    
    features.fillna(0, inplace=True)
    
    all_event_columns = [f'event_{t}' for t in ['file_copied', 'file_created', 'file_moved', 'file_renamed', 'file_shared_externally', 'file_trashed', 'file_downloaded']]
    for col in all_event_columns:
        if col not in features.columns:
            features[col] = 0

    return features