# app/analysis/ntw.py (Final Version with Clear Normalization)

from app.db import dao
from app.analysis.event_risk import calculate_event_risk_score
from app.analysis.narrative_builder import analyze_narratives_for_file, analyze_mass_deletion_for_user
from app.analysis.ml_risk import calculate_ml_risk_score
from app.analysis.contextual_risk import calculate_contextual_risk_score

# --- RE-TUNED WEIGHTS ---
WEIGHTS = { "NR": 0.35, "MR": 0.15, "ER": 0.30, "CR": 0.20 }

# --- NEW: Define the "100% threat" score for each dimension for normalization ---
# We've decided that a score of 25 represents a "100% threat" in any single category.
# This makes the numbers consistent. For example, a mass deletion (raw score 20) is
# an 80% threat on the Narrative scale (20 / 25).
MAX_SCORE_PER_DIMENSION = 25.0

def get_final_threat_score(event: dict) -> dict:
    """
    The main orchestrator, using clear normalization before applying weights.
    """
    er_score, er_reasons = 0.0, []
    nr_score, nr_reasons = 0.0, []
    cr_score, cr_reasons = 0.0, []
    mr_score, mr_reasons = 0.0, []

    with dao.get_db_connection() as conn:
        cursor = conn.cursor()

        er_score, er_reasons = calculate_event_risk_score(cursor, event)
        cr_score, cr_reasons = calculate_contextual_risk_score(cursor, event, er_score)
        mr_score, mr_reasons = calculate_ml_risk_score(cursor, event)
        
        file_id = event.get('file_id')
        user_id = event.get('actor_user_id')
        if file_id:
            file_nr_score, file_nr_reasons = analyze_narratives_for_file(cursor, file_id)
            nr_score += file_nr_score
            nr_reasons.extend(file_nr_reasons)
        if user_id:
            user_nr_score, user_nr_reasons = analyze_mass_deletion_for_user(cursor, user_id)
            nr_score += user_nr_score
            nr_reasons.extend(user_nr_reasons)

    # --- NEW: Clear Normalization Step ---
    # Convert each raw score to a 0-100 scale based on our defined maximum.
    er_normalized = min(er_score / MAX_SCORE_PER_DIMENSION, 1.0) * 100
    nr_normalized = min(nr_score / MAX_SCORE_PER_DIMENSION, 1.0) * 100
    cr_normalized = min(cr_score / MAX_SCORE_PER_DIMENSION, 1.0) * 100
    mr_normalized = min(mr_score / MAX_SCORE_PER_DIMENSION, 1.0) * 100
    
    # Calculate the final weighted score from the 0-100 normalized scores
    final_score = (
        (er_normalized * WEIGHTS["ER"]) +
        (nr_normalized * WEIGHTS["NR"]) +
        (cr_normalized * WEIGHTS["CR"]) +
        (mr_normalized * WEIGHTS["MR"])
    )
    
    output = {
        "final_score": final_score,
        "threat_level": "Low",
        "breakdown": {
            # We report the 0-100 normalized score for clarity
            "ER": {"score": er_normalized, "weight": WEIGHTS["ER"], "reasons": er_reasons},
            "NR": {"score": nr_normalized, "weight": WEIGHTS["NR"], "reasons": nr_reasons},
            "CR": {"score": cr_normalized, "weight": WEIGHTS["CR"], "reasons": cr_reasons},
            "MR": {"score": mr_normalized, "weight": WEIGHTS["MR"], "reasons": mr_reasons},
        }
    }

    if final_score >= 70: output["threat_level"] = "Critical"
    elif final_score >= 40: output["threat_level"] = "High"
    elif final_score >= 20: output["threat_level"] = "Medium"
    
    return output

# --- Update the Test Harness to show the 0-100 scale ---
def test_scoring_harness():
    print("\n--- Running Final Weighted NTW Framework Analysis ---")
    with dao.get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT e.*, f.is_shared_externally, f.vt_positives, f.created_time, f.modified_time, ub.typical_activity_hours_json FROM events e LEFT JOIN files f ON e.file_id = f.id LEFT JOIN user_baseline ub ON e.actor_user_id = ub.user_id WHERE e.actor_user_id IS NOT NULL ORDER BY e.ts DESC LIMIT 3")
        recent_events = cursor.fetchall()

        if not recent_events:
            print("No events to score.")
            return

        for event in recent_events:
            event_dict = dict(event)
            result = get_final_threat_score(event_dict)
            
            print("\n" + "="*60)
            print(f"Scoring Event ID: {event_dict['id']} ({event_dict['event_type']})")
            print(f"Final Weighted Score: {result['final_score']:.2f}/100 ({result['threat_level']})")
            print("Breakdown (Normalized Score * Weight = Contribution):")
            
            er = result['breakdown']['ER']
            nr = result['breakdown']['NR']
            cr = result['breakdown']['CR']
            mr = result['breakdown']['MR']
            
            print(f"  - Event Risk (ER):     {er['score']:.2f}/100 * {er['weight']} = {er['score']*er['weight']:.2f}")
            for reason in er['reasons']: print(f"    - {reason}")
            
            print(f"  - Narrative Risk (NR): {nr['score']:.2f}/100 * {nr['weight']} = {nr['score']*nr['weight']:.2f}")
            for reason in nr['reasons']: print(f"    - {reason}")

            print(f"  - Contextual Risk (CR):{cr['score']:.2f}/100 * {cr['weight']} = {cr['score']*cr['weight']:.2f}")
            for reason in cr['reasons']: print(f"    - {reason}")

            print(f"  - ML Risk (MR):        {mr['score']:.2f}/100 * {mr['weight']} = {mr['score']*mr['weight']:.2f}")
            for reason in mr['reasons']: print(f"    - {reason}")
    print("="*60)