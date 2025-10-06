# app/analysis/ml_risk.py (FIXED - Handles None cursor)

import joblib
import json
import pandas as pd
from pathlib import Path
import logging
logger = logging.getLogger(__name__)

from app.db import dao
from app import config

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
        logger.warning(f"Supervised ML model v2 not found. ML score will be 0.")
except Exception as e:
    model = None
    training_columns = None
    logger.error(f"Could not load supervised ML model v2: {e}")


def calculate_ml_risk_score(cursor, event: dict, micro_pattern_features: dict) -> float:
    """
    Calculates a maliciousness probability using the trained v2 model.
    FIXED: cursor can be None.
    """
    if model is None or training_columns is None:
        return 0.0

    feature_dict = {col: 0.0 for col in training_columns}

    event_ts = event.get('ts')
    if not isinstance(event_ts, pd.Timestamp):
        event_ts = pd.to_datetime(event_ts)
        
    feature_dict['hour_of_day'] = event_ts.hour
    feature_dict['day_of_week'] = event_ts.dayofweek
    
    event_type_col = f"event_{event.get('event_type')}"
    if event_type_col in feature_dict:
        feature_dict[event_type_col] = 1.0

    for feature_name, value in micro_pattern_features.items():
        if feature_name in feature_dict:
            feature_dict[feature_name] = value

    live_features_df = pd.DataFrame([feature_dict], columns=training_columns)
    
    try:
        malicious_probability = model.predict_proba(live_features_df)[:, 1][0]
    except Exception as e:
        logger.error(f"Error during ML prediction: {e}")
        return 0.0
        
    return float(malicious_probability)