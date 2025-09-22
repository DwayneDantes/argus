# app/analysis/ntw.py (Final Version with Narrative Confidence Weighting)

from app.db import dao
from app.analysis.event_risk import calculate_event_risk_score
from app.analysis.narrative_builder import analyze_narratives_for_file, analyze_mass_deletion_for_user
from app.analysis.ml_risk import calculate_ml_risk_score
from app.analysis.contextual_risk import calculate_contextual_risk_score

# --- Define the bonus percentage for each amplifier ---
AMPLIFIER_BONUS = {
    "OFF_HOURS": 0.50,      # +50% score
    "DORMANT_FILE": 0.75,   # +75% score
    "ML_ANOMALY": 1.00       # +100% score (Doubles the score)
}

# --- This is the new orchestrator implementing your design ---
def get_final_threat_score(event: dict) -> dict:
    """
    The main orchestrator, implementing the Narrative Confidence Weighting framework.
    """
    with dao.get_db_connection() as conn:
        cursor = conn.cursor()

        # --- Stage 1: Gather Raw Intelligence from all Specialists ---
        er_score, er_reasons = calculate_event_risk_score(cursor, event)
        cr_score, cr_reasons = calculate_contextual_risk_score(cursor, event)
        mr_score, mr_reasons = calculate_ml_risk_score(cursor, event)
        
        nr_score = 0.0
        nr_reasons = []
        file_id = event.get('file_id')
        user_id = event.get('actor_user_id')
        if file_id:
            file_nr_score, file_nr_reasons = analyze_narratives_for_file(cursor, file_id)
            nr_score += file_nr_score
            nr_reasons.extend(file_nr_reasons)
        if user_id:
            user_nr_score, user_nr_reasons_user = analyze_mass_deletion_for_user(cursor, user_id)
            nr_score += user_nr_score
            nr_reasons.extend(user_nr_reasons_user)

    # --- Stage 2: Blended Score Synthesis ---
    
    # 2a. Calculate Narrative Confidence (0.0 to 1.0)
    # We define that a raw score of 30.0 represents 100% confidence in a narrative.
    narrative_confidence = min(1.0, nr_score / 30.0)
    
    primary_score = 0.0
    secondary_score = 0.0
    
    # 2b. Tiered Blending Logic
    if narrative_confidence > 0.7:  # High confidence narrative
        primary_score = nr_score
        secondary_score = max(er_score, cr_score, mr_score) * 0.3
        tier = "High Confidence Narrative"
    elif narrative_confidence > 0.3:  # Medium confidence narrative  
        primary_score = nr_score * 0.7 + er_score * 0.3
        secondary_score = max(cr_score, mr_score) * 0.2
        tier = "Medium Confidence Narrative"
    else:  # Low/no narrative confidence
        primary_score = er_score
        secondary_score = nr_score * 0.2
        tier = "Event-Driven"
        
    base_threat_score = primary_score + secondary_score

    # --- Stage 3: Multiplicative Amplification ---
    total_amplification = 0.0
    active_amplifiers = []
    
    if "ER: Activity occurred outside of typical hours" in er_reasons:
        total_amplification += AMPLIFIER_BONUS["OFF_HOURS"]
        active_amplifiers.append(f"Off-Hours Activity (+{AMPLIFIER_BONUS['OFF_HOURS'] * 100}%)")
    if cr_reasons: # Check if the CR specialist found anything
        total_amplification += AMPLIFIER_BONUS["DORMANT_FILE"] # Assuming CR is just dormancy for now
        active_amplifiers.append(f"Dormant File (+{AMPLIFIER_BONUS['DORMANT_FILE'] * 100}%)")
    if mr_score > 0:
        total_amplification += AMPLIFIER_BONUS["ML_ANOMALY"]
        active_amplifiers.append(f"ML Anomaly (+{AMPLIFIER_BONUS['ML_ANOMALY'] * 100}%)")

    # --- Final Calculation ---
    final_score = base_threat_score * (1 + total_amplification)
    final_score = min(final_score, 100.0) # Cap the final score at 100

    output = {
        "final_score": final_score,
        "threat_level": "Low",
        "breakdown": {
            "tier": tier,
            "narrative_confidence": narrative_confidence * 100, # As percentage
            "base_threat_score": base_threat_score,
            "amplifiers": active_amplifiers,
            "calculation": f"{base_threat_score:.2f} * (1 + {total_amplification:.2f}) = {final_score:.2f}"
        },
        # Including raw scores for full explainability
        "raw_scores": { "ER": er_score, "NR": nr_score, "CR": cr_score, "MR": mr_score }
    }

    if final_score >= 70: output["threat_level"] = "Critical"
    elif final_score >= 40: output["threat_level"] = "High"
    elif final_score >= 20: output["threat_level"] = "Medium"
    
    return output

# --- Update the Test Harness to show the new sophisticated format ---
def test_scoring_harness():
    print("\n--- Running Narrative Confidence Weighting Framework Analysis ---")
    with dao.get_db_connection() as conn:
        cursor = conn.cursor()
        
        cursor.execute("SELECT e.*, f.name, f.is_shared_externally, f.vt_positives, f.created_time, f.modified_time, ub.typical_activity_hours_json FROM events e LEFT JOIN files f ON e.file_id = f.id LEFT JOIN user_baseline ub ON e.actor_user_id = ub.user_id WHERE e.actor_user_id IS NOT NULL ORDER BY e.ts DESC LIMIT 3")
        recent_events = cursor.fetchall()

        if not recent_events:
            print("No events to score.")
            return

        for event in recent_events:
            event_dict = dict(event)
            result = get_final_threat_score(event_dict)
            
            print("\n" + "="*60)
            print(f"Scoring Event ID: {event_dict['id']} ({event_dict['event_type']}) on file '{event_dict.get('name', 'N/A')}'")
            print(f"Final Score: {result['final_score']:.2f}/100 ({result['threat_level']})")
            print("-" * 60)
            
            bd = result['breakdown']
            raw = result['raw_scores']

            print(f"Logic Tier: '{bd['tier']}' (Narrative Confidence: {bd['narrative_confidence']:.1f}%)")
            print(f"Raw Scores: ER={raw['ER']:.2f}, NR={raw['NR']:.2f}, CR={raw['CR']:.2f}, MR={raw['MR']:.2f}")
            print(f"Blended Base Score: {bd['base_threat_score']:.2f}")

            if bd['amplifiers']:
                print("Active Amplifiers:")
                for amp in bd['amplifiers']:
                    print(f"  - {amp}")
            
            print(f"Final Calculation: {bd['calculation']}")
    print("="*60)