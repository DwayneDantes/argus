# app/guardian/service.py (FIXED - Database Locking & Scheduling Issues)

import time
from pathlib import Path
from PIL import Image
from pystray import Icon as icon, MenuItem as item
from apscheduler.schedulers.background import BackgroundScheduler
from plyer import notification
from datetime import datetime
import logging
import sqlite3

logger = logging.getLogger(__name__)

from app.oauth.google_auth import get_credentials
from app.drive.ingest import ingest_once
from app.analysis.ntw import get_final_threat_score
from app.analysis.baseline_analyzer import update_baseline
from app.analysis.threat_scanner import scan_unscanned_files
from app.db import dao

# CRITICAL FIX: Prevent tasks from running simultaneously
task_lock = {"ingestion": False, "analysis": False, "scanner": False, "learning": False}

def run_ingestion_task():
    if task_lock["ingestion"]:
        print("GUARDIAN: Ingestion task already running, skipping this cycle.")
        return
    
    task_lock["ingestion"] = True
    print(f"\nGUARDIAN: [SCHEDULED TASK] Running data ingestion at {time.strftime('%H:%M:%S')}...")
    try:
        creds = get_credentials()
        ingest_once(creds)
        print("GUARDIAN: Ingestion task completed.")
    except sqlite3.OperationalError as e:
        if "locked" in str(e):
            print("GUARDIAN: Database temporarily locked, will retry next cycle.")
        else:
            print(f"GUARDIAN: Database error during ingestion: {e}")
    except Exception as e:
        print(f"GUARDIAN: ERROR during ingestion task: {e}")
    finally:
        task_lock["ingestion"] = False

def run_learning_task():
    if task_lock["learning"]:
        print("GUARDIAN: Learning task already running, skipping.")
        return
    
    task_lock["learning"] = True
    print(f"\nGUARDIAN: [SCHEDULED TASK] Running baseline learning at {time.strftime('%H:%M:%S')}...")
    try:
        update_baseline()
        print("GUARDIAN: Baseline learning task completed.")
    except sqlite3.OperationalError as e:
        if "locked" in str(e):
            print("GUARDIAN: Database temporarily locked, will retry later.")
        else:
            print(f"GUARDIAN: Database error during learning: {e}")
    except Exception as e:  
        print(f"GUARDIAN: ERROR during learning task: {e}")
    finally:
        task_lock["learning"] = False

def run_scanner_task():
    if task_lock["scanner"]:
        print("GUARDIAN: Scanner task already running, skipping this cycle.")
        return
    
    task_lock["scanner"] = True
    print(f"\nGUARDIAN: [SCHEDULED TASK] Running threat scanner at {time.strftime('%H:%M:%S')}...")
    try:
        scan_unscanned_files()
    except sqlite3.OperationalError as e:
        if "locked" in str(e):
            print("GUARDIAN: Database temporarily locked, will retry next cycle.")
        else:
            print(f"GUARDIAN: Database error during scanning: {e}")
    except Exception as e:
        print(f"GUARDIAN: ERROR during scanner task: {e}")
    finally:
        task_lock["scanner"] = False

def run_analysis_once():
    """Scans all unprocessed events in the database ONE TIME."""
    logger.info("--- Kicking off single analysis run ---")
    
    try:
        with dao.get_db_connection() as conn:
            cursor = conn.cursor()
            
            query = "SELECT e.*, f.name, f.mime_type FROM events e LEFT JOIN files f ON e.file_id = f.id WHERE e.is_analyzed = 0 ORDER BY e.ts ASC"
            unprocessed_events = cursor.execute(query).fetchall()

            if unprocessed_events:
                logger.info(f"Found {len(unprocessed_events)} new events to analyze.")
                for event_row in unprocessed_events:
                    event_dict = dict(event_row)
                    event_id = event_dict['id']
                    
                    # CRITICAL FIX: Mark as analyzed FIRST and commit
                    dao.update_event_analysis_status(cursor, event_id, 1)
                    conn.commit()
                    
                    # NOW score the event (which may save a narrative in a separate connection)
                    result = get_final_threat_score(event_dict)

                    if result['threat_level'] in ['High', 'Critical']:
                        logger.warning(f"High threat event detected! ID: {event_id}, Score: {result['final_score']:.2f}")
                        if result.get('narrative_info'):
                            logger.critical(f"*** NARRATIVE DETECTED AND SAVED: {result['narrative_info']['narrative_type']} ***")

                logger.info("Analysis run complete. All changes committed.")
            else:
                logger.info("No new events to analyze.")

    except Exception as e:
        import traceback
        logger.error(f"ERROR during analysis run: {e}")
        traceback.print_exc()

def run_analysis_tasks():
    if task_lock["analysis"]:
        print("GUARDIAN: Analysis task already running, skipping this cycle.")
        return
    
    task_lock["analysis"] = True
    print(f"\nGUARDIAN: [SCHEDULED TASK] Running analysis suite at {time.strftime('%H:%M:%S')}...")
    try:
        with dao.get_db_connection() as conn:
            print("GUARDIAN: Analyzing new, unprocessed events...")
            cursor = conn.cursor()
            query = "SELECT e.*, f.name, f.mime_type FROM events e LEFT JOIN files f ON e.file_id = f.id WHERE e.is_analyzed = 0"
            cursor.execute(query)
            unprocessed_events = cursor.fetchall()
            
            if unprocessed_events:
                print(f"GUARDIAN: Found {len(unprocessed_events)} new events to analyze.")
                for event in unprocessed_events:
                    event_dict = dict(event)
                    event_id = event_dict['id']
                    
                    # CRITICAL FIX: Mark as analyzed and commit BEFORE scoring
                    dao.update_event_analysis_status(cursor, event_id, 1)
                    conn.commit()
                    
                    # NOW score (may open separate connection for narrative)
                    result = get_final_threat_score(event_dict)

                    if result['threat_level'] in ['High', 'Critical']:
                        logic_tier = result['breakdown']['logic_tier']
                        primary_reason = "No specific reason found."

                        if logic_tier == "Narrative-Driven":
                            reasons_list = result['breakdown']['nr_details']['reasons']
                            if reasons_list:
                                primary_reason = reasons_list[0]
                        else:
                            reasons_list = result['breakdown']['er_details']['reasons']
                            if reasons_list:
                                primary_reason = reasons_list[-1]
                        
                        title = f"{result['threat_level']} Threat Detected ({logic_tier})"
                        message = f"Score: {result['final_score']:.0f}/100. Reason: {primary_reason}"
                        send_notification(title, message)
            else:
                print("GUARDIAN: No new events to analyze.")
        
        print("GUARDIAN: Analysis suite completed.")
    except sqlite3.OperationalError as e:
        if "locked" in str(e):
            print("GUARDIAN: Database temporarily locked, will retry next cycle.")
        else:
            print(f"GUARDIAN: Database error during analysis: {e}")
    except Exception as e:
        import traceback
        print(f"GUARDIAN: ERROR during analysis task: {e}")
        traceback.print_exc()
    finally:
        task_lock["analysis"] = False

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
    
    # FIXED: Stagger the tasks to prevent simultaneous database access
    scheduler.add_job(run_ingestion_task, 'interval', minutes=2, id='ingestion_job')
    scheduler.add_job(run_analysis_tasks, 'interval', minutes=2, id='analysis_job', next_run_time=datetime.now())
    scheduler.add_job(run_scanner_task, 'interval', minutes=5, id='scanner_job')
    scheduler.add_job(run_learning_task, 'cron', hour=2, id='learning_job')
    
    print("GUARDIAN: All jobs scheduled. Running initial tasks now...")
    scheduler.add_job(run_ingestion_task, 'date', run_date=datetime.now())
    
    scheduler.start()
    print("GUARDIAN: Scheduler started. Service is now fully operational.")
    send_notification("Argus Guardian is Active", "Continuously monitoring your Google Drive.")
    setup_tray_icon()
    print("GUARDIAN: Service has been shut down.")