# app/analysis/ntw.py (Final Version with Threat Escalation Framework)

from app.db import dao
from app.analysis.event_risk import calculate_event_risk_score
from app.analysis.narrative_builder import analyze_narratives_for_file, analyze_mass_deletion_for_user
from app.analysis.ml_risk import calculate_ml_risk_score
from app.analysis.contextual_risk import calculate_contextual_risk_score # This import now works

# --- Define the bonus percentage for each amplifier ---
AMPLIFIER_BONUS = {
    "OFF_HOURS": 0.50,    # 50% score increase
    "IS_DORMANT": 0.75, # 75% score increase
    "IS_ARCHIVE": 0.25, # 25% score increase for .zip files etc.
    "IS_ANOMALY": 1.00     # 100% score increase (doubles the score)
}

def get_final_threat_score(event: dict) -> dict:
    """
    The main orchestrator, implementing the Threat Escalation Framework.
    """
    with dao.get_db_connection() as conn:
        cursor = conn.cursor()

        # --- Step 1: Gather Intelligence from all Specialists ---
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
        if user_id:
            user_nr_score, user_nr_reasons_user = analyze_mass_deletion_for_user(cursor, user_id)
            nr_score += user_nr_score
            nr_reasons.extend(file_nr_reasons) # Combine file and user narratives
            nr_reasons.extend(user_nr_reasons_user)


    # --- Step 2: Determine the Primary Threat Vector ---
    primary_threat_score = max(er_score, nr_score)
    primary_threat_reasons = nr_reasons if nr_score > er_score else er_reasons

    # --- Step 3: Identify Active Risk Amplifiers ---
    total_amplification = 0.0
    active_amplifiers = []
    
    if "ER: Activity occurred outside of typical hours" in er_reasons:
        total_amplification += AMPLIFIER_BONUS["OFF_HOURS"]
        active_amplifiers.append(f"Amplified by Off-Hours Activity (+{AMPLIFIER_BONUS['OFF_HOURS'] * 100}%)")

    # Check for contextual amplifiers
    if "CR: Action on an old, dormant file" in cr_reasons:
        total_amplification += AMPLIFIER_BONUS["IS_DORMANT"]
        active_amplifiers.append(f"Amplified by Dormant File (+{AMPLIFIER_BONUS['IS_DORMANT'] * 100}%)")
    if "CR: Event involves a compressed archive file" in cr_reasons:
        total_amplification += AMPLIFIER_BONUS["IS_ARCHIVE"]
        active_amplifiers.append(f"Amplified by Archive File (+{AMPLIFIER_BONUS['IS_ARCHIVE'] * 100}%)")

    if mr_reasons:
        total_amplification += AMPLIFIER_BONUS["IS_ANOMALY"]
        active_amplifiers.append(f"Amplified by ML Anomaly Detection (+{AMPLIFIER_BONUS['IS_ANOMALY'] * 100}%)")

    # --- Step 4: Calculate the Final Escalated Score ---
    final_score = primary_threat_score * (1 + total_amplification)
    final_score = min(final_score, 100.0)

    output = {
        "final_score": final_score,
        "threat_level": "Low",
        "breakdown": {
            "primary_threat": {"score": primary_threat_score, "reasons": primary_threat_reasons},
            "amplifiers": {"count": len(active_amplifiers), "reasons": active_amplifiers},
            "calculation": f"{primary_threat_score:.2f} * (1 + {total_amplification:.2f}) = {final_score:.2f}"
        }
    }

    if final_score >= 70: output["threat_level"] = "Critical"
    elif final_score >= 40: output["threat_level"] = "High"
    elif final_score >= 20: output["threat_level"] = "Medium"
    
    return output

def test_scoring_harness():
    # ... (The test harness code from the previous step is correct and does not need to change) ...
    print("\n--- Running Threat Escalation Framework Analysis ---")
    with dao.get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT e.*, f.name, f.is_shared_externally, f.vt_positives, f.created_time, f.modified_time, ub.typical_activity_hours_json FROM events e LEFT JOIN files f ON e.file_id = f.id LEFT JOIN user_baseline ub ON e.actor_user_id = ub.user_id WHERE e.actor_user_id IS NOT NULL ORDER BY e.ts DESC LIMIT 5")
        recent_events = cursor.fetchall()

        if not recent_events:
            print("No events to score.")
            return

        for event in recent_events:
            event_dict = dict(event)
            result = get_final_threat_score(event_dict)
            
            print("\n" + "="*60)
            print(f"Scoring Event ID: {event_dict['id']} ({event_dict['event_type']}) on file '{event_dict.get('name', 'N/A')}'")
            print(f"Final Escalated Score: {result['final_score']:.2f}/100 ({result['threat_level']})")
            print("Breakdown:")
            
            primary = result['breakdown']['primary_threat']
            amps = result['breakdown']['amplifiers']
            
            print(f"  - Primary Threat Score: {primary['score']:.2f}")
            for reason in primary['reasons']: print(f"    - {reason}")
            
            if amps['count'] > 0:
                print(f"  - Risk Amplifiers ({amps['count']} found):")
                for reason in amps['reasons']: print(f"    - {reason}")
            
            print(f"  - Final Calculation: {result['breakdown']['calculation']}")
    print("="*60)