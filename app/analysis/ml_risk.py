import os
import joblib
import json
import pandas as pd
from pathlib import Path

from ml_utils.feature_engineering import generate_feature_matrix
from app.db import dao
from app import config # Import the central config

# --- Load all ML artifacts using paths from the config file ---
try:
    # Build the full, absolute path here using the config variables
    model_filename = config.SUPERVISED_ML_CONFIG['model_filename']
    columns_filename = config.SUPERVISED_ML_CONFIG['columns_filename']

    model_path = os.path.join(config.MODEL_DIR, model_filename)
    columns_path = os.path.join(config.MODEL_DIR, columns_filename)

    if os.path.exists(model_path) and os.path.exists(columns_path):
        model_artifact = joblib.load(model_path)
        model = model_artifact['model'] # Extract the classifier
        
        # Best Practice: Use the optimized threshold from the artifact itself.
        optimized_threshold = model_artifact['threshold']
        config.SUPERVISED_ML_CONFIG['prosecutor_min_confidence'] = optimized_threshold
        
        
        
        with open(columns_path, 'r') as f:
            training_columns = json.load(f)
        print("INFO: Supervised ML model and training columns loaded successfully.")
    else:
        model = None
        training_columns = None
        print(f"WARNING: Supervised ML model ({model_path}) or columns file ({columns_path}) not found. ML score will be 0.")
except Exception as e:
    model = None
    training_columns = None
    print(f"ERROR: Could not load the supervised ML model. ML score will be 0. Error: {e}")



def calculate_ml_risk_score(cursor, event: dict) -> float:
    """
    Calculates a maliciousness probability score using the trained, supervised
    XGBoost model. This function implements the full history-aware inference pipeline.

    Args:
        cursor: The database cursor for fetching historical context.
        event: The new, incoming event dictionary to be scored.

    Returns:
        A float between 0.0 and 1.0 representing the probability of the event being malicious.
    """
    if model is None or training_columns is None:
        return 0.0

    user_id = event.get('actor_user_id')
    if not user_id:
        return 0.0 # Cannot score events without a user context

    # --- Step 1: Gather Contextual Data (The Inference Pipeline Blueprint) ---
    historical_events_rows = dao.get_events_for_user_context(cursor, user_id, window_days=2)
    all_events = [dict(row) for row in historical_events_rows] + [event]
    events_df = pd.DataFrame(all_events)

    # --- Step 2: Fetch and Convert Baselines and File Details for the Feature Generator ---
    baseline_row = dao.get_user_baseline(cursor, user_id)
    user_baselines = {user_id: dict(baseline_row) if baseline_row else {}}
    
    all_file_ids = events_df['file_id'].dropna().unique()
    file_details_map = {}
    for file_id in all_file_ids:
        details_row = dao.get_file_details(cursor, file_id)
        file_details_map[file_id] = dict(details_row) if details_row else {}

    # --- Step 3: Generate the Full Feature Matrix using the Shared Library ---
    X_live = generate_feature_matrix(events_df, user_baselines, file_details_map)

    if X_live.empty:
        return 0.0

    # --- Step 4: Align Columns to Match Training Order (Crucial Step) ---
    X_live_aligned = X_live.reindex(columns=training_columns, fill_value=0)

    # --- Step 5: Make the Prediction ---
    features_for_new_event = X_live_aligned.tail(1)
    
    # --- DEBUGGING: START ---
    # Let's inspect the 'model' variable right before we use it.
    print("\n--- DEBUG INFO ---")
    print(f"Type of 'model' variable: {type(model)}")
    print(f"Content of 'model' variable: {model}")
    print("--- END DEBUG INFO ---\n")
    # --- DEBUGGING: END ---

    # Use predict_proba to get the probability of the "malicious" class (class 1)
    malicious_probability = model.predict_proba(features_for_new_event)[:, 1][0]
    
    return float(malicious_probability)