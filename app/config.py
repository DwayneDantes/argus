# app/config.py (FINAL, WITH ALL ML CONFIG)

import os
from pathlib import Path

"""
Central configuration file for the Argus security application.
This file contains all tunable parameters, thresholds, and scores.
"""

# --- Core Paths ---
# We define a base directory for models to keep things organized.
MODEL_DIR = Path.home() / ".argus/ml_models"


# --- Event Risk & Heuristics (heuristic_risk.py) ---
EVENT_BASE_SCORES = {
    'file_created': 1.0, 'file_copied': 2.0, 'file_renamed': 1.0, 'file_moved': 1.0,
    'file_modified': 2.0, 'file_trashed': 5.0, 'file_deleted_permanently': 10.0,
    'file_shared_externally': 8.0, 'file_made_public': 20.0, 'permission_change_internal': 1.0
}
EVENT_PROPERTY_SCORES = {
    "KNOWN_MALWARE": 90.0, # This is a critical override
    "PUBLIC_EXPOSURE": EVENT_BASE_SCORES['file_made_public'],
    "SUSPICIOUS_EXTENSION": 15.0, "MIME_MISMATCH": 10.0,
}
OFF_HOURS_MULTIPLIER = 1.5


# --- Contextual Risk (contextual_risk.py) ---
CONTEXTUAL_RISK_ADDITIONS = {
    "DORMANT_FILE": 7.0, "COMPRESSED_ARCHIVE": 4.0, "BURST_ACTIVITY": 8.0,
}
BURST_ACTIVITY_THRESHOLD = 15


# --- Narrative Risk (narrative_builder.py) ---
NARRATIVE_TEMPLATES = {
    'EXFILTRATION_V1': {
        'time_window_minutes': 60,
        'stage_weights': { 'copied': 5.0, 'renamed': 10.0, 'shared': 15.0 }
    }
}
NARRATIVE_BASE_SCORES = {
    'mass_deletion': 20.0, 'ransomware_footprint': 25.0,
}


# --- NEW: Supervised Machine Learning Config (ml_risk.py) ---
SUPERVISED_ML_CONFIG = {
    # --- THIS IS THE CHANGE ---
    # Just provide the filename. We will join it with MODEL_DIR in the code that uses it.
    'model_filename': "argus_tuned_hybrid_model.joblib",
    'columns_filename': "training_columns.json",
    # --- END OF CHANGE ---

    # We will use the F1-optimized threshold found during tuning.
    # This gives the best balance of Precision and Recall.
    'prosecutor_min_confidence': 0.30,

    'score_mapping_slope': 90.0
}


# --- Orchestrator (ntw.py) ---
NARRATIVE_CONFIDENCE_MAX_SCORE = 30.0
NARRATIVE_CONFIDENCE_THRESHOLD = 0.75
NARRATIVE_CONFIDENCE_SHARPNESS = 10.0
AMPLIFIER_BONUSES = {
    "OFF_HOURS_ACTIVITY": 0.5, "DORMANT_FILE_ACTIVATION": 0.75, "COMPRESSED_ARCHIVE": 0.25,
}
MAX_AMPLIFIER_BONUS = 2.0