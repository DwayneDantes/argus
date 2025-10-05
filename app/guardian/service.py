# app/guardian/service.py (FINAL, DE-COUPLED ARCHITECTURE)

import time
from pathlib import Path
from PIL import Image
from pystray import Icon as icon, MenuItem as item
from apscheduler.schedulers.background import BackgroundScheduler
from plyer import notification
from datetime import datetime

from app.oauth.google_auth import get_credentials
from app.drive.ingest import ingest_once
from app.analysis.ntw import get_final_threat_score
from app.analysis.baseline_analyzer import update_baseline
# --- UPDATED: The scanner is now a top-level import ---
from app.analysis.threat_scanner import scan_unscanned_files
from app.db import dao

def run_ingestion_task():
    print(f"\nGUARDIAN: [SCHEDULED TASK] Running data ingestion at {time.strftime('%H:%M:%S')}...")
    try:
        creds = get_credentials()
        ingest_once(creds)
        print("GUARDIAN: Ingestion task completed.")
    except Exception as e:
        print(f"GUARDIAN: ERROR during ingestion task: {e}")

def run_learning_task():
    print(f"\nGUARDIAN: [SCHEDULED TASK] Running baseline learning at {time.strftime('%H:%M:%S')}...")
    try:
        update_baseline()
        print("GUARDIAN: Baseline learning task completed.")
    except Exception as e:  
        print(f"GUARDIAN: ERROR during learning task: {e}")

# --- NEW: A dedicated, standalone task for the threat scanner ---
def run_scanner_task():
    """A separate, scheduled task for the slow VirusTotal scanner."""
    print(f"\nGUARDIAN: [SCHEDULED TASK] Running threat scanner at {time.strftime('%H:%M:%S')}...")
    try:
        # The scanner now handles its own connection and logic.
        scan_unscanned_files()
    except Exception as e:
        print(f"GUARDIAN: ERROR during scanner task: {e}")


def run_analysis_tasks():
    """
    This task is now lean and focused ONLY on scoring new events.
    """
    print(f"\nGUARDIAN: [SCHEDULED TASK] Running analysis suite at {time.strftime('%H:%M:%S')}...")
    try:
        with dao.get_db_connection() as conn:
            # ... (The entire analysis logic remains the same) ...
            print("GUARDIAN: Analyzing new, unprocessed events...")
            cursor = conn.cursor()
            query = "SELECT e.*, f.name, f.mime_type, f.is_shared_externally, f.vt_positives, f.created_time, f.modified_time, ub.typical_activity_hours_json FROM events e LEFT JOIN files f ON e.file_id = f.id LEFT JOIN user_baseline ub ON e.actor_user_id = ub.user_id WHERE e.is_analyzed = 0"
            cursor.execute(query)
            unprocessed_events = cursor.fetchall()
            if unprocessed_events:
                print(f"GUARDIAN: Found {len(unprocessed_events)} new events to analyze.")
                for event in unprocessed_events:
                    event_dict = dict(event)
                    event_id = event_dict['id']
                    result = get_final_threat_score(event_dict)
                    dao.update_event_analysis_status(cursor, event_id, 1)
                    if result['threat_level'] in ['High', 'Critical']:
                        bd = result['breakdown']; scores = {"Event Risk": bd['er_details']['score'],"Narrative Risk": bd['nr_details']['score'],"Contextual Risk": bd['cr_details']['score']}
                        if 'mr_details' in bd: scores["ML Risk"] = bd['mr_details']['score']
                        primary_category = max(scores, key=scores.get)
                        if primary_category == "ML Risk": details_key = "mr_details"
                        else: details_key = f"{primary_category.split()[0].lower()}_details"
                        reasons_list = bd[details_key]['reasons']
                        primary_reason = reasons_list[-1] if reasons_list else f"High {primary_category}"
                        send_notification(f"{result['threat_level']} Threat Detected!", f"Score: {result['final_score']:.0f}/100. Reason: {primary_reason}")
                conn.commit()
            else:
                print("GUARDIAN: No new events to analyze.")
        
        # --- REMOVED: The scanner is no longer called from here ---
        print("GUARDIAN: Analysis suite completed.")
    except Exception as e:
        import traceback
        print(f"GUARDIAN: ERROR during analysis task: {e}")
        traceback.print_exc()

# --- send_notification, setup_tray_icon, on_exit are unchanged ---
def send_notification(title, message):
    print(f"GUARDIAN: Sending notification: '{title}'")
    try:
        notification.notify(title=title, message=message, app_name='Argus Guardian', timeout=20)
    except Exception as e:
        print(f"GUARDIAN: ERROR sending notification: {e}")

def setup_tray_icon():
    icon_path = Path(__file__).parent / "icon.png"
    if icon_path.exists():
        image = Image.open(icon_path)
        menu = (item('Exit', on_exit),)
        tray_icon = icon('ArgusGuardian', image, "Argus Guardian", menu)
        print("GUARDIAN: System tray icon is running.")
        tray_icon.run()
    else:
        print("GUARDIAN: icon.png not found, running without tray icon.")

def on_exit(icon, item):
    print("GUARDIAN: Exit requested. Shutting down scheduler and icon...")
    scheduler.shutdown(wait=False)
    if icon: icon.stop()

scheduler = BackgroundScheduler()

def start_guardian_service():
    print("GUARDIAN: Starting Argus Guardian Service...")
    
    # --- UPDATED: Adjust the scanner schedule ---
    # The scanner job now runs every minute. In each run, it processes a batch
    # of up to 4 files, which respects the VirusTotal API limit.
    scheduler.add_job(run_ingestion_task, 'interval', minutes=1, id='ingestion_job')
    scheduler.add_job(run_analysis_tasks, 'interval', minutes=1, id='analysis_job')
    scheduler.add_job(run_scanner_task, 'interval', minutes=1, id='scanner_job') # Changed from 30 seconds
    scheduler.add_job(run_learning_task, 'cron', hour=2, id='learning_job')
    
    print("GUARDIAN: All jobs scheduled. Running initial tasks now...")
    scheduler.add_job(run_ingestion_task, 'date', run_date=datetime.now())
    scheduler.add_job(run_learning_task, 'date', run_date=datetime.now())
    scheduler.add_job(run_scanner_task, 'date', run_date=datetime.now())
    
    scheduler.start()
    print("GUARDIAN: Scheduler started. Service is now fully operational.")
    send_notification("Argus Guardian is Active", "Continuously monitoring your Google Drive.")
    setup_tray_icon()
    print("GUARDIAN: Service has been shut down.")