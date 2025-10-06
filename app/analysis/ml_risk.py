# app/analysis/ml_risk.py (UPGRADED for Sprint 3)

import os
import joblib
import json
import pandas as pd
from pathlib import Path
import logging
logger = logging.getLogger(__name__)

from app.db import dao
from app import config

# --- 1. Load the NEW v2 Model and Columns ---
try:
    model_path = config.MODEL_DIR / 'argus_model_v2.joblib'
    columns_path = config.MODEL_DIR / 'training_columns_v2.json'

    if model_path.exists() and columns_path.exists():
        model = joblib.load(model_path)
        with open(columns_path, 'r') as f:
            training_columns = json.load(f)
        logger.info("Supervised ML model v2 and training columns loaded successfully.")
    else:
        model = None
        training_columns = None
        logger.warning(f"Supervised ML model v2 ({model_path}) not found. ML score will be 0.")
except Exception as e:
    model = None
    training_columns = None
    logger.error(f"Could not load supervised ML model v2. ML score will be 0. Error: {e}")


def calculate_ml_risk_score(cursor, event: dict, micro_pattern_features: dict) -> float:
    """
    Calculates a maliciousness probability using the trained v2 model.
    This function now accepts pre-computed micro-pattern features.
    """
    if model is None or training_columns is None:
        return 0.0

    # --- 2. Construct the Feature Vector ---
    # Start with a dictionary of all possible features, initialized to 0
    feature_dict = {col: 0.0 for col in training_columns}

    # Fill in stateless features from the event itself
    event_ts = event.get('ts')
    if not isinstance(event_ts, pd.Timestamp):
        event_ts = pd.to_datetime(event_ts)
        
    feature_dict['hour_of_day'] = event_ts.hour
    feature_dict['day_of_week'] = event_ts.dayofweek
    
    event_type_col = f"event_{event.get('event_type')}"
    if event_type_col in feature_dict:
        feature_dict[event_type_col] = 1.0

    # Fill in the stateful micro-pattern features passed from the aggregator
    for feature_name, value in micro_pattern_features.items():
        if feature_name in feature_dict:
            feature_dict[feature_name] = value

    # The 'iforest_score' is part of the training columns, but we don't compute it live for now.
    # It will default to 0, which is a safe baseline.
    
    # --- 3. Create DataFrame and Predict ---
    # Convert the dictionary to a DataFrame in the correct column order
    live_features_df = pd.DataFrame([feature_dict], columns=training_columns)
    
    # Use predict_proba to get the probability of the "malicious" class (class 1)
    try:
        malicious_probability = model.predict_proba(live_features_df)[:, 1][0]
    except Exception as e:
        logger.error(f"Error during ML prediction: {e}")
        return 0.0
        
    return float(malicious_probability)