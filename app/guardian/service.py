# app/guardian/service.py (Final Version with VT Fast-Path Alerting)

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
from app.db.dao import get_db_connection

# (run_ingestion_task and run_learning_task are unchanged)
def run_ingestion_task():
    print(f"GUARDIAN: [SCHEDULED TASK] Running data ingestion at {time.strftime('%H:%M:%S')}...")
    try:
        creds = get_credentials()
        ingest_once(creds)
        print("GUARDIAN: Ingestion task completed.")
    except Exception as e:
        print(f"GUARDIAN: ERROR during ingestion task: {e}")

def run_learning_task():
    print(f"GUARDIAN: [SCHEDULED TASK] Running baseline learning at {time.strftime('%H:%M:%S')}...")
    try:
        update_baseline()
        print("GUARDIAN: Baseline learning task completed.")
    except Exception as e:
        print(f"GUARDIAN: ERROR during learning task: {e}")


# --- THIS IS THE UPGRADED ANALYSIS FUNCTION ---
def run_analysis_tasks():
    """
    Runs the full analysis suite with a special "Fast-Path" for critical
    malware alerts.
    """
    print(f"GUARDIAN: [SCHEDULED TASK] Running analysis suite at {time.strftime('%H:%M:%S')}...")
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            # Query for all necessary data for recent events
            cursor.execute("""
                SELECT e.*, f.name, f.vt_positives FROM events e
                LEFT JOIN files f ON e.file_id = f.id
                WHERE e.ts >= datetime('now', '-30 minutes')
                ORDER BY e.ts DESC
            """)
            recent_events = cursor.fetchall()

            if not recent_events:
                print("GUARDIAN: No new events to analyze.")
            else:
                # --- NEW: Fast-Path Malware Check ---
                # Before any complex scoring, we do a quick loop for confirmed malware.
                for event in recent_events:
                    if event['vt_positives'] is not None and event['vt_positives'] > 0:
                        # If we find one, we send an IMMEDIATE alert.
                        send_notification(
                            "CRITICAL THREAT: MALWARE DETECTED!",
                            f"File '{event['name']}' is a known threat ({event['vt_positives']} detections). Immediate review recommended."
                        )
                        # We could optionally 'return' here to stop further analysis,
                        # but it's better to score it anyway for the logs.

                # --- Standard NTW Scoring for ALL recent events (for logging) ---
                print(f"GUARDIAN: Analyzing {len(recent_events)} new events with NTW framework...")
                for event in recent_events:
                    # We need the full joined data for the orchestrator
                    cursor.execute("SELECT e.*, f.name, f.mimeType, f.is_shared_externally, f.vt_positives, f.created_time, f.modified_time, ub.typical_activity_hours_json FROM events e LEFT JOIN files f ON e.file_id = f.id LEFT JOIN user_baseline ub ON e.actor_user_id = ub.user_id WHERE e.id = ?", (event['id'],))
                    full_event_data = cursor.fetchone()
                    
                    if full_event_data:
                        event_dict = dict(full_event_data)
                        result = get_final_threat_score(event_dict)
                        
                        # The standard notification for other high-threat events still exists
                        if result['threat_level'] in ['High', 'Critical']:
                             # We add a check to avoid sending a DUPLICATE notification for the malware
                            if not (event['vt_positives'] and event['vt_positives'] > 0):
                                send_notification(
                                    f"{result['threat_level']}-Threat Narrative Detected!",
                                    f"Score: {result['final_score']:.0f}/100 for a '{event_dict['event_type']}' event."
                                )
        
        # The slow background scanner for the backlog still runs after the analysis
        print("GUARDIAN: Starting slow scan for known threats (VirusTotal)...")
        scan_unscanned_files()
        
        print("GUARDIAN: Analysis suite completed.")
    except Exception as e:
        print(f"GUARDIAN: ERROR during analysis task: {e}")

# (The rest of the file: send_notification, setup_tray_icon, etc., is unchanged)
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
    scheduler.add_job(run_ingestion_task, 'interval', minutes=15, id='ingestion_job')
    scheduler.add_job(run_analysis_tasks, 'interval', minutes=30, id='analysis_job')
    scheduler.add_job(run_learning_task, 'cron', hour=2, id='learning_job')
    print("GUARDIAN: All jobs scheduled. Running initial tasks now...")
    scheduler.add_job(run_ingestion_task, 'date', run_date=datetime.now())
    scheduler.add_job(run_learning_task, 'date', run_date=datetime.now())
    scheduler.start()
    print("GUARDIAN: Scheduler started. Service is now fully operational.")
    send_notification("Argus Guardian is Active", "Continuously monitoring and learning your activity.")
    setup_tray_icon()
    print("GUARDIAN: Service has been shut down.")