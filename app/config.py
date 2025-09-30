# app/config.py (FINAL, CLEANED UP)

"""
Central configuration file for the Argus security application.
This file contains all tunable parameters, thresholds, and scores.
"""

# --- Event Risk (event_risk.py) ---
EVENT_BASE_SCORES = {
    'file_created': 1.0, 'file_copied': 2.0, 'file_renamed': 1.0, 'file_moved': 1.0,
    'file_modified': 2.0, 'file_trashed': 5.0, 'file_deleted_permanently': 1.0,
    'file_shared_externally': 8.0, 'file_made_public': 20.0, 'permission_change_internal': 1.0
}
EVENT_PROPERTY_SCORES = {
    "KNOWN_MALWARE": 25.0, "PUBLIC_EXPOSURE": EVENT_BASE_SCORES['file_made_public'],
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
        'stage_weights': {
            'copied': 5.0,
            'renamed': 10.0,
            'shared': 15.0
        }
    }
}

NARRATIVE_BASE_SCORES = {
    'mass_deletion': 20.0,
    'ransomware_footprint': 25.0
    # 'rename_and_share' has been removed.
}


# --- ML Risk (ml_risk.py) ---
ML_ANOMALY_THRESHOLDS = { "CRITICAL": 0.60, "HIGH": 0.55, "MODERATE": 0.52 }
ML_RISK_SCORES = { "CRITICAL": 25.0, "HIGH": 18.0, "MODERATE": 10.0 }


# --- Orchestrator (ntw.py) ---
NARRATIVE_CONFIDENCE_MAX_SCORE = 30.0
NARRATIVE_CONFIDENCE_THRESHOLD = 0.75
NARRATIVE_CONFIDENCE_SHARPNESS = 10.0
AMPLIFIER_BONUSES = {
    "OFF_HOURS_ACTIVITY": 0.5, "DORMANT_FILE_ACTIVATION": 0.75, "COMPRESSED_ARCHIVE": 0.25,
}
MAX_AMPLIFIER_BONUS = 2.0