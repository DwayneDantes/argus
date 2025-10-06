# app/guardian/service.py (FINAL, CORRECTED, AND ROBUST)

import time
from pathlib import Path
from PIL import Image
from pystray import Icon as icon, MenuItem as item
from apscheduler.schedulers.background import BackgroundScheduler
from plyer import notification
from datetime import datetime
import logging
logger = logging.getLogger(__name__)

from app.oauth.google_auth import get_credentials
from app.drive.ingest import ingest_once
from app.analysis.ntw import get_final_threat_score
from app.analysis.baseline_analyzer import update_baseline
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

def run_scanner_task():
    """A separate, scheduled task for the slow VirusTotal scanner."""
    print(f"\nGUARDIAN: [SCHEDULED TASK] Running threat scanner at {time.strftime('%H:%M:%S')}...")
    try:
        # The scanner now handles its own connection and logic.
        scan_unscanned_files()
    except Exception as e:
        print(f"GUARDIAN: ERROR during scanner task: {e}")

def run_analysis_once():
    """
    Scans all unprocessed events in the database ONE TIME, scores them,
    and persists any detected narratives.
    """
    logger.info("--- Kicking off single analysis run ---")
    
    try:
        with dao.get_db_connection() as conn:
            cursor = conn.cursor()
            
            # This is the same logic from the Guardian's loop
            query = "SELECT e.*, f.name, f.mime_type FROM events e LEFT JOIN files f ON e.file_id = f.id WHERE e.is_analyzed = 0 ORDER BY e.ts ASC"
            unprocessed_events = cursor.execute(query).fetchall()

            if unprocessed_events:
                logger.info(f"Found {len(unprocessed_events)} new events to analyze.")
                for event_row in unprocessed_events:
                    event_dict = dict(event_row)
                    event_id = event_dict['id']
                    
                    # Call the main orchestrator
                    result = get_final_threat_score(event_dict)

                    # Mark the event as analyzed
                    dao.update_event_analysis_status(cursor, event_id, 1)

                    if result['threat_level'] in ['High', 'Critical']:
                        logger.warning(f"High threat event detected! ID: {event_id}, Score: {result['final_score']:.2f}")
                        if result.get('narrative_info'):
                            logger.critical(f"*** NARRATIVE DETECTED AND SAVED: {result['narrative_info']['narrative_type']} ***")
                        # You can re-enable notifications here if you want
                        # send_notification(f"{result['threat_level']} Threat Detected!", f"Score: {result['final_score']:.0f}")

                conn.commit()
                logger.info("Analysis run complete. All changes committed.")
            else:
                logger.info("No new events to analyze.")

    except Exception as e:
        import traceback
        logger.error(f"ERROR during analysis run: {e}")
        traceback.print_exc()

# --- END OF NEW FUNCTION ---

def run_analysis_tasks():
    """
    This task is now lean and focused ONLY on scoring new events.
    """
    print(f"\nGUARDIAN: [SCHEDULED TASK] Running analysis suite at {time.strftime('%H:%M:%S')}...")
    try:
        with dao.get_db_connection() as conn:
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

                    # --- >>> FIX IS HERE: Robust notification logic <<< ---
                    if result['threat_level'] in ['High', 'Critical']:
                        logic_tier = result['breakdown']['logic_tier']
                        primary_reason = "No specific reason found."

                        # Prioritize the narrative reason if it's the driver
                        if logic_tier == "Narrative-Driven":
                            reasons_list = result['breakdown']['nr_details']['reasons']
                            if reasons_list:
                                primary_reason = reasons_list[0]
                        # Otherwise, use the event-driven reason
                        else:
                            reasons_list = result['breakdown']['er_details']['reasons']
                            if reasons_list:
                                # The last reason added is often the most significant
                                primary_reason = reasons_list[-1]
                        
                        title = f"{result['threat_level']} Threat Detected ({logic_tier})"
                        message = f"Score: {result['final_score']:.0f}/100. Reason: {primary_reason}"
                        send_notification(title, message)
                
                conn.commit()
            else:
                print("GUARDIAN: No new events to analyze.")
        
        print("GUARDIAN: Analysis suite completed.")
    except Exception as e:
        import traceback
        print(f"GUARDIAN: ERROR during analysis task: {e}")
        traceback.print_exc()

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
    
    scheduler.add_job(run_ingestion_task, 'interval', minutes=1, id='ingestion_job')
    scheduler.add_job(run_analysis_tasks, 'interval', minutes=1, id='analysis_job')
    scheduler.add_job(run_scanner_task, 'interval', minutes=1, id='scanner_job')
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