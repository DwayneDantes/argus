# app/guardian/service.py (Definitive Version)

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

def run_ingestion_task():
    """Runs the main data ingestion process."""
    print(f"GUARDIAN: [SCHEDULED TASK] Running data ingestion at {time.strftime('%H:%M:%S')}...")
    try:
        creds = get_credentials()
        ingest_once(creds)
        print("GUARDIAN: Ingestion task completed.")
    except Exception as e:
        print(f"GUARDIAN: ERROR during ingestion task: {e}")

def run_analysis_tasks():
    """
    Runs the full analysis suite: threat scoring for recent events AND the slow
    background scan for known malware (VirusTotal).
    """
    print(f"GUARDIAN: [SCHEDULED TASK] Running analysis suite at {time.strftime('%H:%M:%S')}...")
    try:
        # --- Part 1: Analyze recent events for immediate threats ---
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM events
                WHERE ts >= datetime('now', '-30 minutes')
                ORDER BY ts DESC
            """)
            recent_events = cursor.fetchall()

            if not recent_events:
                print("GUARDIAN: No new events to analyze in this period.")
            else:
                print(f"GUARDIAN: Analyzing {len(recent_events)} new events...")
                for event in recent_events:
                    event_dict = dict(event)
                    result = get_final_threat_score(event_dict)
                    if result['threat_level'] in ['High', 'Critical']:
                        send_notification(
                            f"{result['threat_level']}-Threat Event Detected!",
                            f"Score: {result['final_score']}/100 for a '{event_dict['event_type']}' event."
                        )
        
        # --- Part 2: Run the slow background scanner for the backlog ---
        # This is the correct place for this call. It runs every time the
        # analysis job is triggered, ensuring the backlog is always being worked on.
        print("GUARDIAN: Starting slow scan for known threats (VirusTotal)...")
        scan_unscanned_files()
        
        print("GUARDIAN: Analysis suite completed.")
    except Exception as e:
        print(f"GUARDIAN: ERROR during analysis task: {e}")

def run_learning_task():
    """Runs the behavioral baseline calculation."""
    print(f"GUARDIAN: [SCHEDULED TASK] Running baseline learning at {time.strftime('%H:%M:%S')}...")
    try:
        update_baseline()
        print("GUARDIAN: Baseline learning task completed.")
    except Exception as e:
        print(f"GUARDIAN: ERROR during learning task: {e}")

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
    """The main entry point for the Guardian service."""
    print("GUARDIAN: Starting Argus Guardian Service...")
    
    # You can set these back to longer intervals for "production"
    # e.g., minutes=15 for ingestion, minutes=30 or hours=1 for analysis
    scheduler.add_job(run_ingestion_task, 'interval', minutes=1, id='ingestion_job')
    scheduler.add_job(run_analysis_tasks, 'interval', minutes=2, id='analysis_job') # Run analysis shortly after ingestion
    scheduler.add_job(run_learning_task, 'cron', hour=2, id='learning_job')
    
    print("GUARDIAN: All jobs scheduled. Running initial tasks now...")
    scheduler.add_job(run_ingestion_task, 'date', run_date=datetime.now())
    scheduler.add_job(run_learning_task, 'date', run_date=datetime.now())

    scheduler.start()
    print("GUARDIAN: Scheduler started. Service is now fully operational.")
    
    send_notification("Argus Guardian is Active", "Continuously monitoring and learning your activity.")
    
    setup_tray_icon()
    
    print("GUARDIAN: Service has been shut down.")