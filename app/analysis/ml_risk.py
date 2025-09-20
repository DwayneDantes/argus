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
    Calculates the Machine Learning Risk (MR) score for an event using the
    pre-trained Isolation Forest model.
    """
    score = 0.0
    reasons = []

    # If the model failed to load, we can't score.
    if model is None:
        return score, reasons

    # 1. Get the necessary data for featurization.
    # The event dictionary already contains most of what we need from the join.
    baseline = event
    file_details = event

    # 2. Convert the event into a numerical feature vector.
    # It MUST be the same format as the data used for training.
    feature_vector = featurize_event(event, baseline, file_details)
    
    # 3. Use the model to predict.
    # The model expects a list of samples, so we wrap our vector in a list.
    # The .predict() method returns -1 for anomalies and 1 for normal data points.
    prediction = model.predict([feature_vector])

    # 4. Translate the prediction into a score.
    if prediction[0] == -1: # -1 signifies an anomaly
        score = 25.0 # Assign the maximum possible score for this dimension
        reasons.append("MR: ML model detected a significant behavioral anomaly")

    return score, reasons