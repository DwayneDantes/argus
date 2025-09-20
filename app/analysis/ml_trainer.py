# app/analysis/ml_trainer.py

import joblib
from pathlib import Path
from sklearn.ensemble import IsolationForest

from app.db import dao
from app.analysis.ml_featurizer import featurize_event, get_feature_names

# Define the path where the trained model will be saved
MODEL_DIR = Path.home() / ".argus"
MODEL_PATH = MODEL_DIR / "argus_model.joblib"
METADATA_PATH = MODEL_DIR / "argus_model_metadata.json"

def train_model():
    """
    Trains the Isolation Forest model on all historical data and saves it to a file.
    """
    print("\n--- Starting Machine Learning Model Training ---")
    
    # 1. Fetch all data from the database.
    print("Fetching all historical events for training...")
    all_events = dao.get_all_events_for_training()

    if not all_events or len(all_events) < 100:
        print(f"WARNING: Not enough data for training ({len(all_events)} events found). A minimum of 100 is recommended.")
        print("Please run the '--scan-all' command or let the Guardian run for a while.")
        return

    print(f"Found {len(all_events)} events. Preparing feature vectors...")

    # 2. Featurize all events into a numerical dataset.
    training_data = []
    for event_row in all_events:
        # The DAO function joins multiple tables. We need to convert the Row object
        # to a dictionary to pass it around.
        event = dict(event_row)
        baseline = event # The baseline data is included in the same row
        file_details = event # The file data is also in the same row
        
        feature_vector = featurize_event(event, baseline, file_details)
        training_data.append(feature_vector)

    # 3. Train the Isolation Forest model.
    print("Training the Isolation Forest model...")
    # 'contamination="auto"' is a smart default that works well for many datasets.
    # n_estimators can be tuned, but 100 is a solid starting point.
    model = IsolationForest(n_estimators=100, contamination="auto", random_state=42)
    
    # The .fit() method is the actual "learning" step.
    model.fit(training_data)

    # 4. Save the trained model and its metadata.
    print(f"Training complete. Saving model to: {MODEL_PATH}")
    MODEL_DIR.mkdir(exist_ok=True) # Ensure the .argus directory exists
    joblib.dump(model, MODEL_PATH)
    
    # It's a best practice to save the feature names along with the model.
    # This helps ensure we use the same features during prediction.
    import json
    metadata = {
        "feature_names": get_feature_names(),
        "training_date": str(datetime.now()),
        "total_events": len(all_events)
    }
    with open(METADATA_PATH, 'w') as f:
        json.dump(metadata, f, indent=4)

    print("--- Model Training Successful ---")

# We need to import datetime for the metadata
from datetime import datetime