# app/analysis/ntw.py (FINAL INTEGRATED VERSION for Sprint 3)

import math
import logging
from app.db import dao
from app.analysis.heuristic_risk import calculate_heuristic_risk_score
from app.analysis.contextual_risk import update_and_compute_micro_patterns
from app.analysis.narrative_builder import analyze_narratives_for_actor
from app.analysis.ml_risk import calculate_ml_risk_score
from app import config

logger = logging.getLogger(__name__)

# --- Helper functions for scoring logic ---
def _sigmoid(x):
    return 1 / (1 + math.exp(-x))

def _calculate_blended_base_score(er_score, nr_score) -> tuple[float, str]:
    narrative_confidence = min(1.0, nr_score / config.NARRATIVE_CONFIDENCE_MAX_SCORE)
    k = config.NARRATIVE_CONFIDENCE_SHARPNESS
    tau_N = config.NARRATIVE_CONFIDENCE_THRESHOLD
    narrative_weight = _sigmoid(k * (narrative_confidence - tau_N))
    
    base_score = (narrative_weight * nr_score) + ((1 - narrative_weight) * er_score)
    
    if narrative_weight > 0.9:
        tier = "Narrative-Driven"
    elif narrative_weight < 0.1:
        tier = "Event-Driven"
    else:
        tier = "Blended"
        
    return base_score, tier

# --- The Main Orchestration Function ---
def get_final_threat_score(event: dict) -> dict:
    """
    Orchestrates the full four-layer analysis pipeline for a single event.
    """
    with dao.get_db_connection() as conn:
        cursor = conn.cursor()
        conn.execute("BEGIN")

        try:
            # --- Logic up to final scoring (no changes here) ---
            er_heuristic_score, er_reasons, er_tags = calculate_heuristic_risk_score(cursor, event)
            micro_pattern_features = update_and_compute_micro_patterns(event)
            completed_narrative = analyze_narratives_for_actor(event.get('actor_user_id'), micro_pattern_features)
            
            if completed_narrative:
                nr_score = completed_narrative.get('score', 0.0)
                nr_reasons = [completed_narrative.get('reason', "Matched a known threat narrative.")]
                narrative_id = dao.create_narrative(cursor, completed_narrative)
                logger.info(f"Successfully registered new narrative '{completed_narrative['narrative_type']}' with ID: {narrative_id}")
            else:
                nr_score = 0.0
                nr_reasons = []

            ml_probability = calculate_ml_risk_score(cursor, event, micro_pattern_features)
            
            ml_reasons = []
            if ml_probability >= config.SUPERVISED_ML_CONFIG['prosecutor_min_confidence']:
                er_ml_score = ml_probability * config.SUPERVISED_ML_CONFIG['score_mapping_slope']
                ml_reasons.append(f"ML Model detected a behavioral threat (Confidence: {ml_probability:.2%})")
                er_tags.append("ML_BEHAVIORAL_THREAT")
            else:
                er_ml_score = 0.0

            er_score = max(er_heuristic_score, er_ml_score)
            if er_ml_score > er_heuristic_score:
                er_reasons.extend(ml_reasons)
            
            if completed_narrative:
                base_threat_score = nr_score
                logic_tier = "Narrative-Driven"
            else:
                base_threat_score, logic_tier = _calculate_blended_base_score(er_score, nr_score)
            
            total_amplifier_bonus = 0.0
            final_score = base_threat_score * (1 + total_amplifier_bonus)
            final_score = min(final_score, 100.0)
            
            conn.commit()

        except Exception as e:
            logger.error(f"Error during threat scoring for event ID {event.get('id')}. Rolling back. Error: {e}", exc_info=True)
            conn.rollback()
            raise

    # --- >>> FIX IS HERE: Final Threat Level Assignment with Policy Enforcement <<< ---
    threat_level = "Low"
    if final_score >= 70:
        # A score in the critical range is only labeled 'Critical' if it is narrative-driven.
        if logic_tier == "Narrative-Driven":
            threat_level = "Critical"
        else:
            # Otherwise, we cap the alert level at 'High' as per system policy.
            threat_level = "High" 
    elif final_score >= 40:
        threat_level = "High"
    elif final_score >= 20:
        threat_level = "Medium"

    output = {
        "final_score": final_score,
        "threat_level": threat_level,
        "tags": er_tags,
        "breakdown": {
            "logic_tier": logic_tier,
            "base_score": base_threat_score,
            "total_amplifier_bonus": total_amplifier_bonus,
            "er_details": {"score": er_score, "reasons": er_reasons},
            "nr_details": {"score": nr_score, "reasons": nr_reasons},
        },
        "narrative_info": completed_narrative
    }
    return output

def test_scoring_harness():
    """
    A simple command-line harness to test the full scoring pipeline on the most
    recent events in the database.
    """
    print("\n--- Running Scoring Harness on Recent Events ---")
    
    with dao.get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Query for the 3 most recent events that have an actor
        query = """
            SELECT e.*, f.name, f.mime_type
            FROM events e 
            LEFT JOIN files f ON e.file_id = f.id 
            WHERE e.actor_user_id IS NOT NULL 
            ORDER BY e.ts DESC 
            LIMIT 3
        """
        recent_events = cursor.execute(query).fetchall()

        if not recent_events:
            print("No recent events with an actor found in the database to score.")
            return

        print(f"Found {len(recent_events)} events to score...\n")

        for event_row in recent_events:
            event_dict = dict(event_row) # Convert the sqlite3.Row to a regular dictionary
            
            print("="*80)
            print(f"Scoring Event ID: {event_dict['id']} | Type: {event_dict['event_type']} | Actor: {event_dict['actor_user_id']}")
            print(f"File: '{event_dict.get('name', 'N/A')}' | Timestamp: {event_dict['ts']}")
            print("-"*80)

            try:
                # Call the main orchestrator function
                result = get_final_threat_score(event_dict)
                
                # Print a clean summary of the results
                print(f"  >>> FINAL SCORE: {result['final_score']:.2f}/100  (Threat Level: {result['threat_level']})")
                print(f"      Logic Tier: {result['breakdown']['logic_tier']}")
                
                print("\n      --- Score Breakdown ---")
                print(f"      Event Risk (ER) Score:     {result['breakdown']['er_details']['score']:.2f}")
                print(f"      Narrative Risk (NR) Score: {result['breakdown']['nr_details']['score']:.2f}")
                
                print("\n      --- Contributing Reasons ---")
                all_reasons = result['breakdown']['er_details']['reasons'] + result['breakdown']['nr_details']['reasons']
                if not all_reasons:
                    print("      - No specific risk factors identified.")
                for reason in all_reasons:
                    print(f"      - {reason}")
                
                if result.get('narrative_info'):
                    print("\n      *** NARRATIVE DETECTED ***")
                    print(f"      - Type: {result['narrative_info']['narrative_type']}")

            except Exception as e:
                print(f"\n      *** ERROR DURING SCORING ***")
                print(f"      - {e}")

            print("="*80 + "\n")