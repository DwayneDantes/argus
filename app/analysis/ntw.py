# app/analysis/ntw.py (COMPLETELY FIXED - No Database Locking)

import math
import logging
from app.db import dao
from app.analysis.heuristic_risk import calculate_heuristic_risk_score
from app.analysis.contextual_risk import update_and_compute_micro_patterns
from app.analysis.narrative_builder import analyze_narratives_for_actor
from app.analysis.ml_risk import calculate_ml_risk_score
from app import config

logger = logging.getLogger(__name__)

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

def get_final_threat_score(event: dict) -> dict:
    """
    Orchestrates the full four-layer analysis pipeline for a single event.
    FIXED: Does all scoring WITHOUT database writes, then saves narrative separately.
    """
    narrative_id = None
    
    try:
        # All scoring happens WITHOUT database transactions
        # Layer 1: Heuristic Risk
        er_heuristic_score, er_reasons, er_tags = calculate_heuristic_risk_score(None, event)
        
        # Layer 2: Contextual Risk (in-memory only)
        micro_pattern_features = update_and_compute_micro_patterns(event)
        
        # Layer 3: Narrative Risk (in-memory FSM)
        completed_narrative = analyze_narratives_for_actor(
            event.get('actor_user_id'), 
            micro_pattern_features,
            event.get('id')
        )
        
        if completed_narrative:
            nr_score = completed_narrative.get('score', 0.0)
            nr_reasons = [completed_narrative.get('reason', "Matched a known threat narrative.")]
        else:
            nr_score = 0.0
            nr_reasons = []

        # Layer 4: ML Risk
        ml_probability = calculate_ml_risk_score(None, event, micro_pattern_features)
        
        ml_reasons = []
        if ml_probability >= config.SUPERVISED_ML_CONFIG['prosecutor_min_confidence']:
            er_ml_score = ml_probability * config.SUPERVISED_ML_CONFIG['score_mapping_slope']
            ml_reasons.append(f"ML Model detected a behavioral threat (Confidence: {ml_probability:.2%})")
            er_tags.append("ML_BEHAVIORAL_THREAT")
        else:
            er_ml_score = 0.0

        # Combine ER scores
        er_score = max(er_heuristic_score, er_ml_score)
        if er_ml_score > er_heuristic_score:
            er_reasons.extend(ml_reasons)
        
        # Calculate final score
        if completed_narrative:
            base_threat_score = nr_score
            logic_tier = "Narrative-Driven"
        else:
            base_threat_score, logic_tier = _calculate_blended_base_score(er_score, nr_score)
        
        total_amplifier_bonus = 0.0
        final_score = base_threat_score * (1 + total_amplifier_bonus)
        final_score = min(final_score, 100.0)
        
        # NOW persist the narrative in a SEPARATE connection
        if completed_narrative:
            try:
                with dao.get_db_connection() as narrative_conn:
                    narrative_cursor = narrative_conn.cursor()
                    
                    narrative_id = dao.create_narrative(narrative_cursor, completed_narrative)
                    logger.info(f"SUCCESS: Narrative '{completed_narrative['narrative_type']}' saved with ID: {narrative_id}")
                    
                    events_with_stages = completed_narrative.get('event_ids', [])
                    if not events_with_stages:
                        events_with_stages = [{
                            'event_id': event.get('id'),
                            'stage': 'final_step'
                        }]
                    
                    if events_with_stages:
                        dao.link_events_to_narrative(narrative_cursor, narrative_id, events_with_stages)
                        logger.info(f"SUCCESS: Linked {len(events_with_stages)} events to narrative {narrative_id}")
                    
                    narrative_conn.commit()
            except Exception as e:
                logger.error(f"Failed to save narrative: {e}", exc_info=True)
                # Don't fail the whole scoring - we still return the score

        logger.debug(f"Event {event.get('id')} scored: {final_score:.2f} ({logic_tier})")

    except Exception as e:
        logger.error(f"Error during threat scoring for event ID {event.get('id')}: {e}", exc_info=True)
        raise

    # Threat level assignment
    threat_level = "Low"
    if final_score >= 70:
        if logic_tier == "Narrative-Driven":
            threat_level = "Critical"
        else:
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
        "narrative_info": completed_narrative,
        "narrative_id": narrative_id
    }
    return output

def test_scoring_harness():
    """A simple command-line harness to test the full scoring pipeline."""
    print("\n--- Running Scoring Harness on Recent Events ---")
    
    with dao.get_db_connection() as conn:
        cursor = conn.cursor()
        
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
            event_dict = dict(event_row)
            
            print("="*80)
            print(f"Scoring Event ID: {event_dict['id']} | Type: {event_dict['event_type']} | Actor: {event_dict['actor_user_id']}")
            print(f"File: '{event_dict.get('name', 'N/A')}' | Timestamp: {event_dict['ts']}")
            print("-"*80)

            try:
                result = get_final_threat_score(event_dict)
                
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
                    print(f"      - Narrative ID: {result.get('narrative_id')}")

            except Exception as e:
                print(f"\n      *** ERROR DURING SCORING ***")
                print(f"      - {e}")

            print("="*80 + "\n")