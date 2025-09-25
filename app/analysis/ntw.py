# app/analysis/ntw.py (FINAL, COMPLETE, AND CORRECTED)

from app.db import dao
from app.analysis.event_risk import calculate_event_risk_score
from app.analysis.narrative_builder import analyze_narratives_for_file, analyze_mass_deletion_for_user, analyze_ransomware_footprint
from app.analysis.ml_risk import calculate_ml_risk_score
from app.analysis.contextual_risk import calculate_contextual_risk_score
from app import config

def _calculate_blended_base_score(er_score, nr_score) -> tuple[float, str]:
    """
    Implements the Narrative Confidence Weighting to produce a blended base score.
    """
    narrative_confidence = min(1.0, nr_score / config.NARRATIVE_CONFIDENCE_MAX_SCORE)
    
    if narrative_confidence > config.NARRATIVE_CONFIDENCE_THRESHOLDS["HIGH"]:
        base_score = nr_score + (er_score * 0.1)
        tier = "Narrative-Driven (High Confidence)"
    elif narrative_confidence > config.NARRATIVE_CONFIDENCE_THRESHOLDS["MEDIUM"]:
        base_score = (nr_score * 0.7) + (er_score * 0.3)
        tier = "Blended (Medium Confidence)"
    else:
        base_score = er_score + (nr_score * 0.2)
        tier = "Event-Driven (Low Confidence)"
        
    return base_score, tier

def get_final_threat_score(event: dict) -> dict:
    """
    The main orchestrator, using config for robust amplifier logic.
    """
    with dao.get_db_connection() as conn:
        cursor = conn.cursor()

        er_score, er_reasons, er_tags = calculate_event_risk_score(cursor, event)
        cr_score, cr_reasons, cr_tags = calculate_contextual_risk_score(cursor, event)
        mr_score, mr_reasons, mr_tags = calculate_ml_risk_score(cursor, event)
        
        nr_score = 0.0
        nr_reasons = []
        file_id = event.get('file_id')
        user_id = event.get('actor_user_id')
        event_ts = event.get('ts')

        if file_id:
            file_nr_score, file_nr_reasons = analyze_narratives_for_file(cursor, file_id)
            nr_score += file_nr_score
            nr_reasons.extend(file_nr_reasons)
        if user_id:
            user_nr_score, user_nr_reasons_user = analyze_mass_deletion_for_user(cursor, user_id)
            nr_score += user_nr_score
            nr_reasons.extend(user_nr_reasons_user)
            if event_ts:
                ransom_nr_score, ransom_nr_reasons = analyze_ransomware_footprint(cursor, user_id, event_ts)
                nr_score += ransom_nr_score
                nr_reasons.extend(ransom_nr_reasons)

    base_threat_score, logic_tier = _calculate_blended_base_score(er_score, nr_score)

    er_amplifier_bonus = 0.0
    if "OFF_HOURS_ACTIVITY" in er_tags:
        er_amplifier_bonus += config.AMPLIFIER_BONUSES["OFF_HOURS_ACTIVITY"]
    cr_amplifier_bonus = 0.0
    if "DORMANT_FILE_ACTIVATION" in cr_tags:
        cr_amplifier_bonus += config.AMPLIFIER_BONUSES["DORMANT_FILE_ACTIVATION"]
    if "COMPRESSED_ARCHIVE" in cr_tags:
        cr_amplifier_bonus += config.AMPLIFIER_BONUSES["COMPRESSED_ARCHIVE"]
    mr_amplifier_bonus = 0.0
    if "ML_CRITICAL_ANOMALY" in mr_tags or "ML_HIGH_ANOMALY" in mr_tags:
        mr_amplifier_bonus += (mr_score / config.ML_RISK_SCORES["CRITICAL"])

    final_score = base_threat_score * (1 + er_amplifier_bonus) * (1 + cr_amplifier_bonus) * (1 + mr_amplifier_bonus)
    final_score = min(final_score, 100.0)

    all_tags = er_tags + cr_tags + mr_tags
    
    output = {
        "final_score": final_score, "threat_level": "Low", "tags": all_tags,
        "breakdown": {
            "logic_tier": logic_tier, "base_score": base_threat_score,
            "er_details": {"score": er_score, "reasons": er_reasons, "amplifier": er_amplifier_bonus},
            "nr_details": {"score": nr_score, "reasons": nr_reasons},
            "cr_details": {"score": cr_score, "reasons": cr_reasons, "amplifier": cr_amplifier_bonus},
            "mr_details": {"score": mr_score, "reasons": mr_reasons, "amplifier": mr_amplifier_bonus},
            "calculation": f"{base_threat_score:.2f} * (1 + {er_amplifier_bonus:.2f}) * (1 + {cr_amplifier_bonus:.2f}) * (1 + {mr_amplifier_bonus:.2f}) = {final_score:.2f}"
        }
    }

    if final_score >= 70: output["threat_level"] = "Critical"
    elif final_score >= 40: output["threat_level"] = "High"
    elif final_score >= 20: output["threat_level"] = "Medium"
    
    return output

# --- RESTORED AND UPGRADED TEST HARNESS ---
def test_scoring_harness():
    """
    A command-line utility to fetch the most recent events from the database
    and run them through the full scoring engine for debugging and tuning.
    """
    print("\n--- Running Final Blended & Cascading Framework Analysis ---")
    with dao.get_db_connection() as conn:
        cursor = conn.cursor()

        query = """
            SELECT 
                e.*, f.name, f.mime_type, f.is_shared_externally, f.vt_positives, 
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
            print("No events to score.")
            return

        for event in recent_events:
            event_dict = dict(event)
            result = get_final_threat_score(event_dict)
            
            print("\n" + "="*70)
            print(f"Scoring Event ID: {event_dict['id']} ({event_dict['event_type']}) on file '{event_dict.get('name', 'N/A')}'")
            print(f"Final Escalated Score: {result['final_score']:.2f}/100 ({result['threat_level']})")
            print(f"Detected Tags: {result.get('tags', [])}") # Added tags to output
            print("-" * 70)
            
            bd = result['breakdown']
            print(f"Logic Tier: '{bd['logic_tier']}' | Blended Base Score: {bd['base_score']:.2f}")
            print("--- Contributing Raw Scores ---")
            print(f"  - Event Risk:     {bd['er_details']['score']:.2f} -> Amplifier: +{bd['er_details']['amplifier']:.0%}")
            print(f"  - Narrative Risk: {bd['nr_details']['score']:.2f}")
            print(f"  - Contextual Risk:{bd['cr_details']['score']:.2f} -> Amplifier: +{bd['cr_details']['amplifier']:.0%}")
            print(f"  - ML Risk:        {bd['mr_details']['score']:.2f} -> Amplifier: +{bd['mr_details']['amplifier']:.0%}")
            print("\n--- Contributing Reasons ---")
            for reason in bd['er_details']['reasons'] + bd['nr_details']['reasons'] + bd['cr_details']['reasons'] + bd['mr_details']['reasons']:
                print(f"  - {reason}")
            
            print("\n--- Final Calculation ---")
            print(f"  {bd['calculation']}")
    print("="*70)