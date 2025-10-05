import pandas as pd
import numpy as np
import re
from .base_featurizer import featurize_event, get_feature_names

# Helper: map MIME types to categories
def categorize_mime(mime: str) -> str:
    if not mime or not isinstance(mime, str):
        return "unknown"
    mime = mime.lower()
    if "msword" in mime or "officedocument" in mime or "presentation" in mime or "spreadsheet" in mime:
        return "office"
    if "pdf" in mime:
        return "pdf"
    if "zip" in mime or "rar" in mime or "7z" in mime:
        return "archive"
    if "text" in mime or "plain" in mime:
        return "text"
    if "image" in mime:
        return "image"
    if "audio" in mime or "video" in mime:
        return "media"
    if "exe" in mime or "application/x-msdownload" in mime:
        return "executable"
    return "other"

# Helper: extract extension
def get_file_extension(filename: str) -> str:
    if not filename or not isinstance(filename, str):
        return "none"
    match = re.search(r"\.([A-Za-z0-9]+)$", filename.lower())
    return match.group(1) if match else "none"

def generate_feature_matrix(events_df: pd.DataFrame, user_baselines: dict, file_details_map: dict) -> pd.DataFrame:
    if events_df.empty:
        return pd.DataFrame()

    # --- FIX: START ---
    # Ensure critical columns like 'size_bytes' exist to prevent KeyErrors.
    # Some events (e.g., permission changes) don't have a file size.
    # If the column is missing, we create it and fill with a safe default of 0.
    if 'size_bytes' not in events_df.columns:
        events_df['size_bytes'] = 0
    # --- FIX: END ---

    user_col = 'actor_user_id' if 'actor_user_id' in events_df.columns else 'actor_email'
    ts_col = 'ts' if 'ts' in events_df.columns else 'timestamp'

    events_df[ts_col] = pd.to_datetime(events_df[ts_col])
    events_df = events_df.sort_values(by=ts_col).reset_index(drop=True)

    # --- Context tracking structures ---
    seen_files = set()
    seen_ips_per_user = {}
    last_event_time_user = {}
    last_event_time_file = {}

    base_feature_vectors = []
    for i, event_row in events_df.iterrows():
        user_id = event_row.get(user_col)
        file_id = event_row.get('file_id')
        ip = event_row.get('ip_address')

        baseline = user_baselines.get(user_id, {})
        file_details = file_details_map.get(file_id, {})
        event_dict = event_row.to_dict()
        event_dict['timestamp'] = event_row[ts_col]

        # Stateless features
        feats = featurize_event(event_dict, baseline, file_details)

        # --- Contextual features ---
        # 1. New file indicator
        feats.append(int(file_id not in seen_files))
        seen_files.add(file_id)

        # 2. Log-scaled file size
        # This line is now safe because we guaranteed the column exists above.
        size = event_row['size_bytes'] if pd.notna(event_row['size_bytes']) else 0
        feats.append(np.log1p(size))

        # 3. New IP indicator
        prev_ips = seen_ips_per_user.get(user_id, set())
        feats.append(int(ip not in prev_ips))
        seen_ips_per_user.setdefault(user_id, set()).add(ip)

        # 4. Time since last event by user
        feats.append((event_row[ts_col] - last_event_time_user[user_id]).total_seconds()
                     if user_id in last_event_time_user else 0)
        last_event_time_user[user_id] = event_row[ts_col]

        # 5. Time since last event on file
        feats.append((event_row[ts_col] - last_event_time_file[file_id]).total_seconds()
                     if file_id in last_event_time_file else 0)
        last_event_time_file[file_id] = event_row[ts_col]

        # --- File content features ---
        # 6. File extension (flag suspicious types)
        ext = get_file_extension(event_row.get("file_name", ""))
        suspicious_exts = {"exe", "js", "bat", "vbs", "ps1"}
        feats.append(int(ext in suspicious_exts))  # suspicious file type flag

        # 7. MIME type category (categorical one-hot later)
        mime_cat = categorize_mime(event_row.get("mime_type", ""))
        feats.append(mime_cat)

        base_feature_vectors.append(feats)

    # Collect feature names
    extra_names = [
        "is_new_file", "file_size_log", "is_new_ip",
        "time_since_last_user_event", "time_since_last_file_event",
        "suspicious_filetype", "mime_category"
    ]
    X_base = pd.DataFrame(base_feature_vectors, index=events_df.index,
                          columns=get_feature_names() + extra_names)

    # One-hot encode MIME category
    mime_dummies = pd.get_dummies(X_base["mime_category"], prefix="mime")
    X_base = pd.concat([X_base.drop(columns=["mime_category"]), mime_dummies], axis=1)

    # --- Rolling 1h user activity (your original winning feature) ---
    temp_df = pd.get_dummies(events_df['event_type'])
    temp_df[user_col] = events_df[user_col]
    temp_df[ts_col] = events_df[ts_col]
    temp_df = temp_df.set_index(ts_col)

    grouped = temp_df.groupby(user_col)
    rolling_features = grouped.rolling('1h').sum()
    rolling_features = rolling_features.reset_index(level=user_col, drop=True)
    rolling_features.columns = [f'user_{col}_count_1h' for col in rolling_features.columns]
    rolling_features.reset_index(drop=True, inplace=True)

    # Combine all features
    X_final = pd.concat([X_base, rolling_features], axis=1)
    X_final.fillna(0, inplace=True)

    return X_final