# app/analysis/ml_risk.py

import joblib
from pathlib import Path

from app.db import dao
from app.analysis.ml_featurizer import featurize_event

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


def calculate_ml_risk_score(cursor, event: dict) -> tuple[float, list[str]]:
    """
    Calculates a nuanced Machine Learning Risk (MR) score using the
    pre-trained Isolation Forest model's anomaly score.
    """
    score = 0.0
    reasons = []

    if model is None:
        return score, reasons

    baseline = event
    file_details = event
    feature_vector = featurize_event(event, baseline, file_details)
    
    # --- UPGRADED LOGIC ---
    # 1. Use .score_samples() to get a raw anomaly score.
    # The method returns a score where more negative = more normal.
    # We flip the sign so that positive = more anomalous.
    raw_anomaly_score = -model.score_samples([feature_vector])[0]

    # 2. Normalize and translate the raw score into our 0-25 point system.
    # These thresholds are a starting point and would be refined with testing.
    # A typical "normal" score is around 0.5. Anything higher is an anomaly.
    if raw_anomaly_score > 0.6: # Critical anomaly
        score = 25.0
        reasons.append(f"MR: ML model detected a CRITICAL behavioral anomaly (raw score: {raw_anomaly_score:.3f})")
    elif raw_anomaly_score > 0.55: # High anomaly
        score = 18.0
        reasons.append(f"MR: ML model detected a HIGH behavioral anomaly (raw score: {raw_anomaly_score:.3f})")
    elif raw_anomaly_score > 0.52: # Medium anomaly
        score = 10.0
        reasons.append(f"MR: ML model detected a MODERATE behavioral anomaly (raw score: {raw_anomaly_score:.3f})")
    
    return score, reasons