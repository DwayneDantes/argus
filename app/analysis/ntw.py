# app/analysis/ntw.py (UPGRADED FOR NARRATIVE PERSISTENCE)

import math
import logging
from app.db import dao
from app.analysis.heuristic_risk import calculate_heuristic_risk_score
from app.analysis.narrative_builder import (
    analyze_exfiltration_by_obfuscation, 
    analyze_mass_deletion_for_user, 
    analyze_ransomware_footprint
)
from app.analysis.ml_risk import calculate_ml_risk_score
from app.analysis.contextual_risk import calculate_contextual_risk_score
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
    
    if narrative_weight > 0.9: tier = "Narrative-Driven"
    elif narrative_weight < 0.1: tier = "Event-Driven"
    else: tier = "Blended"
    return base_score, tier

def get_final_threat_score(event: dict) -> dict:
    with dao.get_db_connection() as conn:
        cursor = conn.cursor()
        conn.execute("BEGIN") # Start a transaction

        try:
            # --- Intelligence Gathering (unchanged) ---
            er_heuristic_score, er_reasons, er_tags = calculate_heuristic_risk_score(cursor, event)
            cr_score, cr_reasons, cr_tags = calculate_contextual_risk_score(cursor, event)
            ml_probability = calculate_ml_risk_score(cursor, event)
            
            # --- Narrative Analysis (UPGRADED) ---
            nr_score = 0.0
            nr_reasons = []
            user_id = event.get('actor_user_id')
            
            # 1. New, Stateful Narrative Analysis
            exfil_hit = analyze_exfiltration_by_obfuscation(event, cursor)
            if exfil_hit:
                logger.info("Exfiltration narrative hit detected. Persisting to database.")
                # Persist the detected narrative to the database
                narrative_id = dao.create_narrative(cursor, exfil_hit)
                dao.link_events_to_narrative(cursor, narrative_id, exfil_hit['contributing_events'])
                
                # Use the results for the current event's score
                nr_score += exfil_hit['score']
                nr_reasons.append(exfil_hit['reason'])
                logger.info(f"Successfully registered new narrative '{exfil_hit['narrative_type']}' with ID: {narrative_id}")
            
            # 2. Legacy, Stateless Narrative Analysis (unchanged)
            if user_id:
                mass_del_score, mass_del_reasons = analyze_mass_deletion_for_user(cursor, user_id)
                nr_score += mass_del_score
                nr_reasons.extend(mass_del_reasons)
                
                ransom_nr_score, ransom_nr_reasons = analyze_ransomware_footprint(cursor, user_id, event['ts'])
                nr_score += ransom_nr_score
                nr_reasons.extend(ransom_nr_reasons)

            # --- Event Risk Calculation (unchanged) ---
            er_ml_score = 0.0
            ml_reasons = []
            if ml_probability >= config.SUPERVISED_ML_CONFIG['prosecutor_min_confidence']:
                er_ml_score = ml_probability * config.SUPERVISED_ML_CONFIG['score_mapping_slope']
                ml_reasons.append(f"ML Model detected a behavioral threat (Confidence: {ml_probability:.2%})")
                er_tags.append("ML_BEHAVIORAL_THREAT")
            
            er_score = max(er_heuristic_score, er_ml_score)
            if er_ml_score > er_heuristic_score:
                 er_reasons.extend(ml_reasons)

            # --- Final Scoring (unchanged) ---
            base_threat_score, logic_tier = _calculate_blended_base_score(er_score, nr_score)
            bonus_pool = 0.0
            if "OFF_HOURS_ACTIVITY" in er_tags: bonus_pool += config.AMPLIFIER_BONUSES["OFF_HOURS_ACTIVITY"]
            if "DORMANT_FILE_ACTIVATION" in cr_tags: bonus_pool += config.AMPLIFIER_BONUSES["DORMANT_FILE_ACTIVATION"]
            if "COMPRESSED_ARCHIVE" in cr_tags: bonus_pool += config.AMPLIFIER_BONUSES["COMPRESSED_ARCHIVE"]
            total_amplifier_bonus = min(config.MAX_AMPLIFIER_BONUS, bonus_pool)
            final_score = base_threat_score * (1 + total_amplifier_bonus); final_score = min(final_score, 100.0)
            
            conn.commit() # Commit the transaction if everything was successful

        except Exception as e:
            logger.error(f"Error during threat scoring. Rolling back transaction. Error: {e}")
            conn.rollback() # Rollback on error to prevent partial data writes
            raise # Re-raise the exception after rolling back

    # --- Formatting Output (unchanged) ---
    all_tags = er_tags + cr_tags
    output = { "final_score": final_score, "threat_level": "Low", "tags": all_tags, "breakdown": { "logic_tier": logic_tier, "base_score": base_threat_score, "total_amplifier_bonus": total_amplifier_bonus, "er_details": {"score": er_score, "reasons": er_reasons}, "nr_details": {"score": nr_score, "reasons": nr_reasons}, "cr_details": {"score": cr_score, "reasons": cr_reasons}, "calculation": f"{base_threat_score:.2f} * (1 + {total_amplifier_bonus:.2f}) = {final_score:.2f}" } }
    if final_score >= 70: output["threat_level"] = "Critical"
    elif final_score >= 40: output["threat_level"] = "High"
    elif final_score >= 20: output["threat_level"] = "Medium"
    return output


def test_scoring_harness():
    print("\n--- Running Final Blended & Cascading Framework Analysis ---")
    with dao.get_db_connection() as conn:
        cursor = conn.cursor()
        query = """
            SELECT e.*, f.name, f.mime_type, f.is_shared_externally, f.vt_positives, 
                   f.created_time, f.modified_time, ub.typical_activity_hours_json 
            FROM events e 
            LEFT JOIN files f ON e.file_id = f.id 
            LEFT JOIN user_baseline ub ON e.actor_user_id = ub.user_id 
            WHERE e.actor_user_id IS NOT NULL 
            ORDER BY e.ts DESC 
            LIMIT 3
        """
        cursor.execute(query)
        recent_events = cursor.fetchall()

        if not recent_events:
            print("No events to score."); return

        for event in recent_events:
            event_dict = dict(event)
            result = get_final_threat_score(event_dict)
            
            # (The rest of the original printing logic follows)
            print("\n" + "="*70)
            print(f"Scoring Event ID: {event_dict['id']} ({event_dict['event_type']}) on file '{event_dict.get('name', 'N/A')}'")
            print(f"Final Escalated Score: {result['final_score']:.2f}/100 ({result['threat_level']})")
            print(f"Detected Tags: {result.get('tags', [])}")
            print("-" * 70)
            bd = result['breakdown']
            print(f"Logic Tier: '{bd['logic_tier']}' | Blended Base Score: {bd['base_score']:.2f}")
            print(f"Total Amplifier Bonus: +{bd['total_amplifier_bonus']:.0%}")
            print("--- Contributing Raw Scores ---")
            print(f"  - Event Risk:     {bd['er_details']['score']:.2f} (Determined by max of Heuristic & ML scores)")
            print(f"  - Narrative Risk: {bd['nr_details']['score']:.2f}")
            print(f"  - Contextual Risk:{bd['cr_details']['score']:.2f}")
            print("\n--- Contributing Reasons ---")
            all_reasons = bd['er_details']['reasons'] + bd['nr_details']['reasons'] + bd['cr_details']['reasons']
            for reason in all_reasons:
                print(f"  - {reason}")
            print("\n--- Final Calculation ---")
            print(f"  {bd['calculation']}")
    print("="*70)