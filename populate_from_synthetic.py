# populate_from_synthetic.py
import sqlite3
import sys
import json
from pathlib import Path
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')

def main():
    """
    Reads from the flat, synthetic dataset and intelligently populates the
    normalized tables (events, files, users, user_baseline) in the main app database.
    """
    project_root = Path(__file__).parent.resolve()
    
    source_db_path = project_root / "tools" / "argus_synthetic_dataset_v4.sqlite"
    dest_db_path = Path.home() / ".argus" / "argus.db"

    if not source_db_path.exists():
        logging.error(f"Source database not found at '{source_db_path}'")
        logging.error("Please run 'python -m tools.generate_dataset' first.")
        sys.exit(1)

    logging.info("Connecting to databases...")
    source_conn = sqlite3.connect(source_db_path)
    source_conn.row_factory = sqlite3.Row
    dest_conn = sqlite3.connect(dest_db_path)

    try:
        logging.info("Reading all synthetic events from source...")
        synthetic_events = source_conn.execute("SELECT * FROM events ORDER BY timestamp ASC").fetchall()
        
        if not synthetic_events:
            logging.warning("No events found in the synthetic dataset. Nothing to ingest.")
            return

        logging.info(f"Found {len(synthetic_events)} events. Populating main application database...")
        
        inserted_files = set()
        inserted_users = set()

        with dest_conn:
            cursor = dest_conn.cursor()
            for event_row in synthetic_events:
                event = dict(event_row)
                
                user_id = event.get('actor_email')
                if user_id and user_id not in inserted_users:
                    cursor.execute(
                        "INSERT OR IGNORE INTO users (id, display_name, email) VALUES (?, ?, ?)",
                        (user_id, user_id.split('@')[0], user_id)
                    )
                    cursor.execute(
                       "INSERT OR IGNORE INTO user_baseline (user_id, typical_activity_hours_json, max_historical_deletions) VALUES (?, ?, ?)",
                       (user_id, json.dumps({'start': '08:00', 'end': '18:00'}), 10)
                    )
                    inserted_users.add(user_id)

                file_id = event.get('file_id')
                if file_id and file_id not in inserted_files:
                    cursor.execute(
                        """
                        INSERT OR IGNORE INTO files (id, name, mime_type, created_time, modified_time) 
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            file_id,
                            event.get('file_name'),
                            event.get('mime_type'),
                            event.get('timestamp'),
                            event.get('timestamp')
                        )
                    )
                    inserted_files.add(file_id)

                # --- THIS IS THE FIX ---
                # We no longer provide a value for the 'id' column. The database
                # will autoincrement it for us.
                cursor.execute(
                    """
                    INSERT INTO events (drive_change_id, file_id, event_type, actor_user_id, ts, details_json, is_analyzed) 
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.get('event_id'), # This goes into the TEXT drive_change_id column
                        file_id,
                        event.get('event_type'),
                        user_id,
                        event.get('timestamp'),
                        event.get('details_json'),
                        0
                    )
                )
                # --- END OF FIX ---

        logging.info("Population complete. All synthetic data has been ingested.")
    
    except Exception as e:
        logging.error(f"An error occurred during population: {e}", exc_info=True)
    finally:
        source_conn.close()
        dest_conn.close()

if __name__ == "__main__":
    main()