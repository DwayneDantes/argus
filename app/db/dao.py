# app/db/dao.py (FINAL, ROBUST VERSION)
import sqlite3
from pathlib import Path
import json
from datetime import datetime

def convert_timestamp_iso(val: bytes) -> datetime:
    """Converts an ISO 8601 timestamp string from the DB into a datetime object."""
    return datetime.fromisoformat(val.decode())

sqlite3.register_converter("timestamp", convert_timestamp_iso)

APP_DIR = Path.home() / ".argus"
DB_FILE = APP_DIR / "argus.db"
SCHEMA_FILE = Path(__file__).parent / "schema.sql"

def get_db_connection() -> sqlite3.Connection:
    APP_DIR.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_FILE, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    return conn

# --- THIS IS THE FINAL FIX ---
def initialize_database():
    """
    Initializes the database from the schema file, but only if the 'events'
    table does not already exist. This makes the function safe to call multiple times.
    """
    # First, check if the database file exists and has tables.
    if DB_FILE.exists() and DB_FILE.stat().st_size > 0:
        try:
            with get_db_connection() as conn:
                # Check for the existence of a key table. If it's there, the DB is initialized.
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='events'")
                if cursor.fetchone():
                    # print("Database already initialized.") # Optional: uncomment for verbose logging
                    return # Exit the function silently
        except sqlite3.DatabaseError:
            # The file might be corrupt or empty, so we proceed to initialize.
            pass

    # If the check fails or the file doesn't exist, proceed with initialization.
    print("Initializing database...")
    try:
        with get_db_connection() as conn:
            with open(SCHEMA_FILE, 'r') as f:
                schema_script = f.read()
            conn.executescript(schema_script)
            conn.commit()
        print("Database ready.")
    except Exception as e:
        print(f"FATAL: Could not initialize database. Error: {e}")
# --- END OF FIX ---


# --- REFACTORED FUNCTION ---
def get_meta_value(cursor: sqlite3.Cursor, key: str) -> str | None:
    """Gets a meta value using the provided database cursor."""
    cursor.execute("SELECT value FROM meta WHERE key = ?", (key,))
    row = cursor.fetchone()
    return row['value'] if row else None

# --- REFACTORED FUNCTION ---
def set_meta_value(cursor: sqlite3.Cursor, key: str, value: str):
    """Sets a meta value using the provided database cursor."""
    cursor.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, value))


def get_file_details(cursor: sqlite3.Cursor, file_id: str) -> sqlite3.Row | None:
    cursor.execute("SELECT id, name, parents_json, modified_time, is_shared_externally, is_shared_publicly FROM files WHERE id = ?", (file_id,))
    return cursor.fetchone()

def find_file_by_checksum(cursor: sqlite3.Cursor, checksum: str, new_file_id: str) -> sqlite3.Row | None:
    cursor.execute( "SELECT id, name FROM files WHERE md5Checksum = ? AND id != ?", (checksum, new_file_id) )
    return cursor.fetchone()

def save_user(cursor: sqlite3.Cursor, user_data: dict):
    cursor.execute( "INSERT OR REPLACE INTO users (id, display_name, email) VALUES (?, ?, ?)", (user_data.get('permissionId'), user_data.get('displayName'), user_data.get('emailAddress')))

def save_file(cursor: sqlite3.Cursor, file_data: dict, is_externally_shared: bool, is_publicly_shared: bool):
    parents_json = json.dumps(file_data.get('parents', []))
    cursor.execute(
        "INSERT OR REPLACE INTO files (id, name, mime_type, created_time, modified_time, trashed, parents_json, md5Checksum, is_shared_externally, is_shared_publicly) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            file_data.get('id'), file_data.get('name'), file_data.get('mimeType'),
            file_data.get('createdTime'), file_data.get('modifiedTime'),
            1 if file_data.get('trashed') else 0, parents_json,
            file_data.get('md5Checksum'), 1 if is_externally_shared else 0,
            1 if is_publicly_shared else 0
        )
    )

def save_event(cursor: sqlite3.Cursor, change_id: str, file_id: str, event_type: str, actor_id: str | None, timestamp: str, details: str):
    cursor.execute( "INSERT OR IGNORE INTO events (drive_change_id, file_id, event_type, actor_user_id, ts, details_json) VALUES (?, ?, ?, ?, ?, ?)", (change_id, file_id, event_type, actor_id, timestamp, details))

def get_user_baseline(cursor: sqlite3.Cursor, user_id: str) -> sqlite3.Row | None:
    cursor.execute("SELECT * FROM user_baseline WHERE user_id = ?", (user_id,))
    return cursor.fetchone()

def update_user_baseline(cursor: sqlite3.Cursor, user_id: str, baseline_data: dict):
    cursor.execute( """ INSERT OR REPLACE INTO user_baseline ( user_id, typical_activity_hours_json, avg_daily_deletions, max_historical_deletions, has_performed_mass_cleanup, last_updated_ts ) VALUES (?, ?, ?, ?, ?, ?) """, ( baseline_data.get('user_id'), baseline_data.get('typical_activity_hours_json'), baseline_data.get('avg_daily_deletions'), baseline_data.get('max_historical_deletions'), baseline_data.get('has_performed_mass_cleanup'), baseline_data.get('last_updated_ts') ) )

def count_recent_deletions(cursor: sqlite3.Cursor, user_id: str, end_ts_str: str) -> int:
    query = """ SELECT COUNT(*) as deletion_count FROM events WHERE actor_user_id = ? AND (event_type = 'file_trashed' OR event_type = 'file_deleted_permanently') AND ts <= ? AND ts >= datetime(?, '-1 hours') """
    cursor.execute(query, (user_id, end_ts_str, end_ts_str))
    result = cursor.fetchone()
    return result['deletion_count'] if result else 0

def get_unscanned_files(cursor: sqlite3.Cursor, limit: int = 20) -> list[sqlite3.Row]:
    cursor.execute( """ SELECT id, md5Checksum FROM files WHERE md5Checksum IS NOT NULL AND vt_scan_ts IS NULL LIMIT ? """, (limit,) )
    return cursor.fetchall()

def update_file_vt_score(cursor: sqlite3.Cursor, file_id: str, positives: int):
    cursor.execute( "UPDATE files SET vt_scan_ts = ?, vt_positives = ? WHERE id = ?", (datetime.now().isoformat(), positives, file_id) )

def get_file_vt_score(cursor: sqlite3.Cursor, file_id: str) -> int | None:
    cursor.execute("SELECT vt_positives FROM files WHERE id = ?", (file_id,))
    result = cursor.fetchone()
    return result['vt_positives'] if result and result['vt_positives'] is not None else None

def count_recent_user_activity(cursor: sqlite3.Cursor, user_id: str, end_ts: datetime, window_minutes: int = 10) -> int:
    """Counts user activity in a window ending at the given datetime object."""
    # Convert the aware datetime object to a string for the SQL query
    end_ts_str = end_ts.isoformat()
    query = f"""
        SELECT COUNT(*) as event_count FROM events WHERE actor_user_id = ? AND ts <= ? AND ts >= datetime(?, '-{window_minutes} minutes')
    """
    cursor.execute(query, (user_id, end_ts_str, end_ts_str))
    result = cursor.fetchone()
    return result['event_count'] if result else 0
def get_priority_unscanned_files(cursor: sqlite3.Cursor, limit: int = 5) -> list[sqlite3.Row]:
    query = """
        SELECT id, md5Checksum FROM files WHERE md5Checksum IS NOT NULL AND vt_scan_ts IS NULL AND created_time >= datetime('now', '-1 day')
        ORDER BY created_time DESC LIMIT ?
    """
    cursor.execute(query, (limit,))
    return cursor.fetchall()

def get_all_events_for_ml_training(cursor: sqlite3.Cursor) -> list[sqlite3.Row]:
    query = """
        SELECT
            e.*, f.name, f.mime_type, f.is_shared_externally, f.is_shared_publicly,
            f.vt_positives, f.created_time, f.modified_time, ub.typical_activity_hours_json
        FROM events e
        LEFT JOIN files f ON e.file_id = f.id
        LEFT JOIN user_baseline ub ON e.actor_user_id = ub.user_id
        WHERE e.actor_user_id IS NOT NULL
    """
    cursor.execute(query)
    return cursor.fetchall()
    
def find_file_by_name(cursor: sqlite3.Cursor, file_name: str) -> sqlite3.Row | None:
    cursor.execute("SELECT id, name, md5Checksum FROM files WHERE name = ?", (file_name,))
    return cursor.fetchone()

def update_event_analysis_status(cursor: sqlite3.Cursor, event_id: int, status: int):
    cursor.execute("UPDATE events SET is_analyzed = ? WHERE id = ?", (status, event_id))

def get_file_event_history(cursor: sqlite3.Cursor, file_id: str, lookback_days: int = 90) -> list[sqlite3.Row]:
    query = """
        SELECT id, event_type, actor_user_id, ts, details_json
        FROM events
        WHERE file_id = ? AND ts >= date('now', ?)
        ORDER BY ts ASC
    """
    lookback_str = f'-{lookback_days} days'
    cursor.execute(query, (file_id, lookback_str))
    return cursor.fetchall()


def get_events_for_user_context(cursor: sqlite3.Cursor, user_id: str, window_days: int = 2) -> list[sqlite3.Row]:
    query = """
        SELECT id, file_id, event_type, actor_user_id, ts
        FROM events
        WHERE actor_user_id = ? AND ts >= date('now', ?)
        ORDER BY ts ASC
    """
    lookback_str = f'-{window_days} days'
    cursor.execute(query, (user_id, lookback_str))
    return cursor.fetchall()

def create_narrative(cursor: sqlite3.Cursor, narrative_data: dict) -> int:
    query = """
        INSERT INTO narratives (narrative_type, primary_actor_id, start_time, end_time, final_score)
        VALUES (?, ?, ?, ?, ?)
    """
    cursor.execute(query, (
        narrative_data['narrative_type'],
        narrative_data['primary_actor_id'],
        narrative_data['start_time'],
        narrative_data['end_time'],
        narrative_data['score']
    ))
    return cursor.lastrowid

def link_events_to_narrative(cursor: sqlite3.Cursor, narrative_id: int, events_with_stages: list[dict]):
    events_to_insert = [
        (narrative_id, event['event_id'], event.get('stage'))
        for event in events_with_stages
    ]
    cursor.executemany(
        "INSERT INTO narrative_events (narrative_id, event_id, stage) VALUES (?, ?, ?)",
        events_to_insert
    )


def get_narrative_details(cursor: sqlite3.Cursor, narrative_id: int) -> sqlite3.Row | None:
    """
    Fetches the header information for a single narrative incident.
    """
    query = "SELECT * FROM narratives WHERE narrative_id = ?"
    cursor.execute(query, (narrative_id,))
    return cursor.fetchone()

def get_events_for_narrative(cursor: sqlite3.Cursor, narrative_id: int) -> list[sqlite3.Row]:
    """
    Fetches the full event details for all events linked to a specific narrative,
    ordered chronologically. This is the core function for building a timeline.
    
    CORRECTED: Uses explicit aliases for all columns to ensure a perfect match
    with the Pydantic model in the API layer.
    """
    query = """
        SELECT
            e.id                AS id,
            e.event_type        AS event_type,
            e.actor_user_id     AS actor_user_id,
            e.ts                AS ts,
            f.name              AS file_name,
            ne.stage            AS stage
        FROM narrative_events ne
        JOIN events e ON ne.event_id = e.id
        LEFT JOIN files f ON e.file_id = f.id
        WHERE ne.narrative_id = ?
        ORDER BY e.ts ASC
    """
    cursor.execute(query, (narrative_id,))
    return cursor.fetchall()