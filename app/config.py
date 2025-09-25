# app/config.py (NEW FILE)

"""
Central configuration file for the Argus security application.
This file contains all tunable parameters, thresholds, and scores.
"""

# --- Event Risk (event_risk.py) ---
# Base scores for different event types
EVENT_BASE_SCORES = {
    'file_created': 1.0,
    'file_copied': 2.0,
    'file_renamed': 1.0,
    'file_moved': 1.0,
    'file_modified': 2.0,
    'file_trashed': 5.0,
    'file_deleted_permanently': 10.0,
    'file_shared_externally': 8.0,
    'file_made_public': 20.0,
    'permission_change_internal': 1.0
}

# Scores for high-risk properties (these override the base score if higher)
EVENT_PROPERTY_SCORES = {
    "KNOWN_MALWARE": 25.0,
    "PUBLIC_EXPOSURE": EVENT_BASE_SCORES['file_made_public'], # Keep it consistent
    "SUSPICIOUS_EXTENSION": 15.0,
    "MIME_MISMATCH": 10.0,
}

# Multiplier for off-hours activity
OFF_HOURS_MULTIPLIER = 1.5


# --- Contextual Risk (contextual_risk.py) ---
# Points added for specific contextual modifiers
CONTEXTUAL_RISK_ADDITIONS = {
    "DORMANT_FILE": 7.0,
    "COMPRESSED_ARCHIVE": 4.0,
    "BURST_ACTIVITY": 8.0,
}

# Threshold for detecting burst activity (actions per 10 minutes)
BURST_ACTIVITY_THRESHOLD = 15


# --- Narrative Risk (narrative_builder.py) ---
NARRATIVE_BASE_SCORES = {
    'data_exfiltration': 15.0,
    'mass_deletion': 20.0,
    'ransomware_footprint': 25.0
}


# --- ML Risk (ml_risk.py) ---
# Raw anomaly score thresholds from the Isolation Forest model
ML_ANOMALY_THRESHOLDS = {
    "CRITICAL": 0.60,
    "HIGH": 0.55,
    "MODERATE": 0.52
}

# Scores assigned for each anomaly tier
ML_RISK_SCORES = {
    "CRITICAL": 25.0,
    "HIGH": 18.0,
    "MODERATE": 10.0
}


# --- Orchestrator (ntw.py) ---
# Blended Base Score configuration
NARRATIVE_CONFIDENCE_THRESHOLDS = {
    "HIGH": 0.7,    # Above this, score is Narrative-Driven
    "MEDIUM": 0.3,  # Above this, score is Blended
                    # Below this, score is Event-Driven
}
NARRATIVE_CONFIDENCE_MAX_SCORE = 30.0 # The NR score at which confidence is 100%

# Cascading Amplifier Bonuses (additive percentage, e.g., 0.5 = +50%)
AMPLIFIER_BONUSES = {
    "OFF_HOURS_ACTIVITY": 0.5,
    "DORMANT_FILE_ACTIVATION": 0.75,
    "COMPRESSED_ARCHIVE": 0.25,
    # ML bonus is calculated proportionally from its score
}