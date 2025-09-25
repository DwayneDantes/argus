# app/guardian/service.py (Corrected and Final)

import time
from pathlib import Path
from PIL import Image
from pystray import Icon as icon, MenuItem as item
from apscheduler.schedulers.background import BackgroundScheduler
from plyer import notification
from datetime import datetime

# --- Import all of our application's real functions ---
from app.oauth.google_auth import get_credentials
from app.drive.ingest import ingest_once
from app.analysis.ntw import get_final_threat_score
from app.analysis.baseline_analyzer import update_baseline
from app.analysis.threat_scanner import scan_unscanned_files
# --- THIS IS THE FIX for the crash ---
from app.db import dao # Import the dao module

def run_ingestion_task():
    # ... (This function is correct and unchanged)
    print(f"GUARDIAN: [SCHEDULED TASK] Running data ingestion at {time.strftime('%H:%M:%S')}...")
    try:
        creds = get_credentials()
        ingest_once(creds)
        print("GUARDIAN: Ingestion task completed.")
    except Exception as e:
        print(f"GUARDIAN: ERROR during ingestion task: {e}")

def run_learning_task():
    # ... (This function is correct and unchanged)
    print(f"GUARDIAN: [SCHEDULED TASK] Running baseline learning at {time.strftime('%H:%M:%S')}...")
    try:
        update_baseline()
        print("GUARDIAN: Baseline learning task completed.")
    except Exception as e:  
        print(f"GUARDIAN: ERROR during learning task: {e}")

# --- THIS IS THE UPGRADED ANALYSIS & ALERTING FUNCTION ---
def run_analysis_tasks():
    """
    Runs the full analysis suite, now with state management to prevent duplicate alerts.
    Correctly parses the orchestrator output to generate meaningful alerts.
    """
    print(f"GUARDIAN: [SCHEDULED TASK] Running analysis suite at {time.strftime('%H:%M:%S')}...")
    
    try:
        print("GUARDIAN: Analyzing new, unprocessed events...")
        with dao.get_db_connection() as conn:
            cursor = conn.cursor()
            
            # --- FIX 1: Select only events that have NOT been analyzed ---
            query = """
                SELECT e.*, f.name, f.mime_type, f.is_shared_externally, f.vt_positives, 
                f.created_time, f.modified_time, ub.typical_activity_hours_json 
                FROM events e
                LEFT JOIN files f ON e.file_id = f.id
                LEFT JOIN user_baseline ub ON e.actor_user_id = ub.user_id
                WHERE e.is_analyzed = 0
            """
            cursor.execute(query)
            unprocessed_events = cursor.fetchall()

            if unprocessed_events:
                print(f"GUARDIAN: Found {len(unprocessed_events)} new events to analyze.")
                for event in unprocessed_events:
                    event_dict = dict(event)
                    event_id = event_dict['id']
                    
                    # Score the event
                    result = get_final_threat_score(event_dict)
                    
                    # --- FIX 3: Immediately mark the event as analyzed to prevent re-processing ---
                    dao.update_event_analysis_status(cursor, event_id, 1) # 1 = Analyzed

                    # --- FIX 2: Correctly parse the new output for alerting ---
                    if result['threat_level'] in ['High', 'Critical']:
                        bd = result['breakdown']
                        # Determine the primary reason for the high score
                        scores = {
                            "Event Risk": bd['er_details']['score'],
                            "Narrative Risk": bd['nr_details']['score'],
                            "Contextual Risk": bd['cr_details']['score'],
                            "ML Risk": bd['mr_details']['score']
                        }
                        primary_category = max(scores, key=scores.get)
                        details_key = f"{primary_category.split()[0].lower()}_details"
                        reasons_list = bd[details_key]['reasons']
                        
                        # Extract the most specific reason
                        primary_reason = reasons_list[-1] if reasons_list else f"High {primary_category}"

                        send_notification(
                            f"{result['threat_level']} Threat Detected!",
                            f"Score: {result['final_score']:.0f}/100. Reason: {primary_reason}"
                        )
                
                conn.commit() # Commit the 'is_analyzed' changes
            else:
                print("GUARDIAN: No new events to analyze.")

        # The slow background scanner can run after the main analysis
        print("GUARDIAN: Starting slow scan for known threats (VirusTotal)...")
        scan_unscanned_files()
        
        print("GUARDIAN: Analysis suite completed.")
    except Exception as e:
        # Added traceback for better error diagnosis
        import traceback
        print(f"GUARDIAN: ERROR during analysis task: {e}")
        traceback.print_exc()

# (The rest of the file is unchanged)
def send_notification(title, message):
    print(f"GUARDIAN: Sending notification: '{title}'")
    try:
        notification.notify(title=title, message=message, app_name='Argus Guardian', timeout=20)
    except Exception as e:
        print(f"GUARDIAN: ERROR sending notification: {e}")
def setup_tray_icon():
    icon_path = Path(__file__).parent / "icon.png"
    image = Image.open(icon_path)
    menu = (item('Exit', on_exit),)
    tray_icon = icon('ArgusGuardian', image, "Argus Guardian", menu)
    print("GUARDIAN: System tray icon is running.")
    tray_icon.run()
def on_exit(icon, item):
    print("GUARDIAN: Exit requested. Shutting down scheduler and icon...")
    scheduler.shutdown(wait=False)
    icon.stop()
scheduler = BackgroundScheduler()
def start_guardian_service():
    print("GUARDIAN: Starting Argus Guardian Service...")
    scheduler.add_job(run_ingestion_task, 'interval', minutes=1, id='ingestion_job')
    scheduler.add_job(run_analysis_tasks, 'interval', minutes=1, id='analysis_job')
    scheduler.add_job(run_learning_task, 'cron', hour=2, id='learning_job')
    print("GUARDIAN: All jobs scheduled. Running initial tasks now...")
    scheduler.add_job(run_ingestion_task, 'date', run_date=datetime.now())
    scheduler.add_job(run_learning_task, 'date', run_date=datetime.now())
    scheduler.start()
    print("GUARDIAN: Scheduler started. Service is now fully operational.")
    send_notification("Argus Guardian is Active", "Continuously monitoring and learning your activity.")
    setup_tray_icon()
    print("GUARDIAN: Service has been shut down.")