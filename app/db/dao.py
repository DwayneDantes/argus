# app/db/dao.py (CORRECTED with proper connection handling)
import sqlite3
from pathlib import Path
import json
from datetime import datetime

APP_DIR = Path.home() / ".argus"
DB_FILE = APP_DIR / "argus.db"
SCHEMA_FILE = Path(__file__).parent / "schema.sql"

def get_db_connection() -> sqlite3.Connection:
    APP_DIR.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_FILE, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    return conn

def initialize_database():
    print("Initializing database...")
    with get_db_connection() as conn:
        with open(SCHEMA_FILE, 'r') as f:
            schema_script = f.read()
        conn.executescript(schema_script)
        conn.commit()
    print("Database ready.")

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

# --- All functions below this line are unchanged, until get_all_events_for_ml_training ---
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

def count_recent_user_activity(cursor: sqlite3.Cursor, user_id: str, end_ts_str: str, window_minutes: int = 10) -> int:
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

# --- REFACTORED FUNCTION ---
def get_all_events_for_ml_training(cursor: sqlite3.Cursor) -> list[sqlite3.Row]:
    """
    Fetches all events and joins them with all necessary data from other tables
    required for the ML featurizer, using the provided database cursor.
    """
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
    """Marks an event as analyzed or un-analyzed."""
    cursor.execute("UPDATE events SET is_analyzed = ? WHERE id = ?", (status, event_id))