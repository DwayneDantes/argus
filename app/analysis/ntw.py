# app/analysis/ntw.py (Corrected Orchestrator)

from app.db import dao
from app.analysis.event_risk import calculate_event_risk_score
from app.analysis.narrative_builder import analyze_narratives_for_file, analyze_mass_deletion_for_user

def get_final_threat_score(event: dict) -> dict:
    """
    This is the main orchestrator function. It takes a raw event and calculates
    the full, multi-dimensional NTW score.
    """
    er_score, er_reasons = 0.0, []
    nr_score, nr_reasons = 0.0, []
    cr_score, cr_reasons = 0.0, []

    with dao.get_db_connection() as conn:
        cursor = conn.cursor()
        er_score, er_reasons = calculate_event_risk_score(cursor, event)
        
        file_id = event.get('file_id')
        if file_id:
            file_nr_score, file_nr_reasons = analyze_narratives_for_file(cursor, file_id)
            nr_score += file_nr_score
            nr_reasons.extend(file_nr_reasons)
        
        user_id = event.get('actor_user_id')
        if user_id:
            user_nr_score, user_nr_reasons = analyze_mass_deletion_for_user(cursor, user_id)
            nr_score += user_nr_score
            nr_reasons.extend(user_nr_reasons)

        cr_score = 5.0 
        cr_reasons.append("CR: Base contextual score")

    er_capped = min(er_score, 25.0)
    nr_capped = min(nr_score, 25.0)
    cr_capped = min(cr_score, 25.0)
    final_score = er_capped + nr_capped + cr_capped
    
    output = {
        "final_score": final_score,
        "threat_level": "Low",
        "breakdown": {
            "ER": {"score": er_capped, "reasons": er_reasons},
            "NR": {"score": nr_capped, "reasons": nr_reasons},
            "CR": {"score": cr_capped, "reasons": cr_reasons},
        }
    }

    if final_score >= 75:
        output["threat_level"] = "Critical"
    elif final_score >= 50:
        output["threat_level"] = "High"
    elif final_score >= 25:
        output["threat_level"] = "Medium"
    
    return output

def test_scoring_harness():
    """
    Test harness to demonstrate the new multi-dimensional scoring.
    """
    print("\n--- Running NTW Framework Analysis on Recent Events ---")
    with dao.get_db_connection() as conn:
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM events ORDER BY ts DESC LIMIT 3")
        recent_events = cursor.fetchall()

        if not recent_events:
            print("No events to score.")
            return

        for event in recent_events:
            event_dict = dict(event)
            result = get_final_threat_score(event_dict)
            
            print("\n" + "="*50)
            print(f"Scoring Event ID: {event_dict['id']} ({event_dict['event_type']})")
            print(f"Final Score: {result['final_score']}/100 ({result['threat_level']})")
            print("Breakdown:")
            er = result['breakdown']['ER']
            nr = result['breakdown']['NR']
            cr = result['breakdown']['CR']
            print(f"  - Event Risk (ER):     {er['score']:.2f}/25")
            for reason in er['reasons']: print(f"    - {reason}")
            print(f"  - Narrative Risk (NR): {nr['score']:.2f}/25")
            for reason in nr['reasons']: print(f"    - {reason}")
            print(f"  - Contextual Risk (CR):{cr['score']:.2f}/25")
            for reason in cr['reasons']: print(f"    - {reason}")
    print("="*50)