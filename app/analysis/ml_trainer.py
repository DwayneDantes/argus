# app/analysis/ml_trainer.py (CORRECTED)

import joblib
from pathlib import Path
from sklearn.ensemble import IsolationForest
from datetime import datetime
import json

from app.db import dao
from app.analysis.ml_featurizer import featurize_event, get_feature_names

MODEL_DIR = Path.home() / ".argus"
MODEL_PATH = MODEL_DIR / "argus_model.joblib"
METADATA_PATH = MODEL_DIR / "argus_model_metadata.json"

def train_model():
    """
    Trains the Isolation Forest model on all historical data and saves it.
    """
    print("\n--- Starting Machine Learning Model Training ---")
    
    print("Fetching all historical events for training...")
    # --- FIX: Open one connection and pass the cursor to the DAO ---
    with dao.get_db_connection() as conn:
        cursor = conn.cursor()
        all_events = dao.get_all_events_for_ml_training(cursor)

    if not all_events or len(all_events) < 50:
        print(f"WARNING: Not enough data for training ({len(all_events)} events found).")
        return

    print(f"Found {len(all_events)} events. Preparing feature vectors...")
    training_data = []
    for event_row in all_events:
        event = dict(event_row)
        feature_vector = featurize_event(event, event, event)
        training_data.append(feature_vector)

    print("Training the Isolation Forest model...")
    model = IsolationForest(n_estimators=100, contamination="auto", random_state=42)
    model.fit(training_data)

    print(f"Training complete. Saving model to: {MODEL_PATH}")
    MODEL_DIR.mkdir(exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    
    metadata = {
        "feature_names": get_feature_names(),
        "training_date": str(datetime.now()),
        "total_events": len(all_events)
    }
    with open(METADATA_PATH, 'w') as f:
        json.dump(metadata, f, indent=4)

    print("--- Model Training Successful ---")