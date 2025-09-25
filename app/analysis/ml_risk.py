# app/analysis/ml_risk.py

import joblib
from pathlib import Path

from app.db import dao
from app.analysis.ml_featurizer import featurize_event
from app import config

# Define the path to the saved model
MODEL_DIR = Path.home() / ".argus"
MODEL_PATH = MODEL_DIR / "argus_model.joblib"

# --- Load the Model ---
# This is a key step. We load the model from the file once when the program starts.
# This is much more efficient than loading it for every single event.
try:
    if MODEL_PATH.exists():
        model = joblib.load(MODEL_PATH)
        print("INFO: Machine Learning model loaded successfully.")
    else:
        model = None
        print("WARNING: Pre-trained ML model not found. Run --train-model to create it. MR score will be 0.")
except Exception as e:
    model = None
    print(f"ERROR: Could not load the ML model. MR score will be 0. Error: {e}")


def calculate_ml_risk_score(cursor, event: dict) -> tuple[float, list[str], list[str]]:
    """
    Calculates ML Risk (MR) score and returns structured tags.
    """
    score = 0.0
    reasons = []
    tags = []

    if model is None:
        return score, reasons, tags

    # ... (featurizing is the same) ...
    baseline = event; file_details = event; feature_vector = featurize_event(event, baseline, file_details)
    raw_anomaly_score = -model.score_samples([feature_vector])[0]

    # --- Use constants from the config file ---
    if raw_anomaly_score > config.ML_ANOMALY_THRESHOLDS["CRITICAL"]:
        score = config.ML_RISK_SCORES["CRITICAL"]
        reasons.append(f"MR: ML model detected a CRITICAL behavioral anomaly (raw score: {raw_anomaly_score:.3f})")
        tags.append("ML_CRITICAL_ANOMALY")
    elif raw_anomaly_score > config.ML_ANOMALY_THRESHOLDS["HIGH"]:
        score = config.ML_RISK_SCORES["HIGH"]
        reasons.append(f"MR: ML model detected a HIGH behavioral anomaly (raw score: {raw_anomaly_score:.3f})")
        tags.append("ML_HIGH_ANOMALY")
    elif raw_anomaly_score > config.ML_ANOMALY_THRESHOLDS["MODERATE"]:
        score = config.ML_RISK_SCORES["MODERATE"]
        reasons.append(f"MR: ML model detected a MODERATE behavioral anomaly (raw score: {raw_anomaly_score:.3f})")
        tags.append("ML_MODERATE_ANOMALY")
    
    return score, reasons, tags