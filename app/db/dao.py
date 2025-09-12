# app/db/dao.py

import sqlite3
from pathlib import Path
import json

APP_DIR = Path.home() / ".argus"
DB_FILE = APP_DIR / "argus.db"
SCHEMA_FILE = Path(__file__).parent / "schema.sql"

def get_db_connection() -> sqlite3.Connection:
    """Establishes a connection to the SQLite database."""
    APP_DIR.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_FILE, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    return conn

def initialize_database():
    """Creates the database and tables from the schema if they don't exist."""
    print("Initializing database...")
    with get_db_connection() as conn:
        with open(SCHEMA_FILE, 'r') as f:
            schema_script = f.read()
        conn.executescript(schema_script)
        conn.commit()
    print("Database ready.")

def get_meta_value(key: str) -> str | None:
    """Retrieves a value from the meta table."""
    # This function remains the same
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM meta WHERE key = ?", (key,))
        row = cursor.fetchone()
        return row['value'] if row else None

def set_meta_value(key: str, value: str):
    """Inserts or updates a value in the meta table."""
    # This function remains the same
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, value))
        conn.commit()

def get_file_details(cursor: sqlite3.Cursor, file_id: str) -> sqlite3.Row | None:
    """Retrieves key details of a file already stored in the database."""
    # This function remains the same
    cursor.execute("SELECT id, name, parents_json, modified_time FROM files WHERE id = ?", (file_id,))
    return cursor.fetchone()

# --- NEW FUNCTION ---
def find_file_by_checksum(cursor: sqlite3.Cursor, checksum: str, new_file_id: str) -> sqlite3.Row | None:
    """Finds an *existing* file with the same checksum, excluding the new file itself."""
    cursor.execute(
        "SELECT id, name FROM files WHERE md5Checksum = ? AND id != ?",
        (checksum, new_file_id)
    )
    return cursor.fetchone()

def save_user(cursor: sqlite3.Cursor, user_data: dict):
    """Saves or updates a user's information."""
    # This function remains the same
    cursor.execute(
        "INSERT OR REPLACE INTO users (id, display_name, email) VALUES (?, ?, ?)",
        (user_data.get('permissionId'), user_data.get('displayName'), user_data.get('emailAddress'))
    )

def save_file(cursor: sqlite3.Cursor, file_data: dict):
    """Saves or updates a file's metadata, including its checksum."""
    parents_json = json.dumps(file_data.get('parents', []))
    cursor.execute(
        # UPDATED to include md5Checksum
        "INSERT OR REPLACE INTO files (id, name, mime_type, created_time, modified_time, trashed, parents_json, md5Checksum) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            file_data.get('id'), file_data.get('name'), file_data.get('mimeType'),
            file_data.get('createdTime'), file_data.get('modifiedTime'),
            1 if file_data.get('trashed') else 0, parents_json,
            file_data.get('md5Checksum') # Added the new field
        )
    )

def save_event(cursor: sqlite3.Cursor, change_id: str, file_id: str, event_type: str, actor_id: str | None, timestamp: str, details: str):
    """Saves a single event to the database."""
    # This function remains the same
    cursor.execute(
        "INSERT OR IGNORE INTO events (drive_change_id, file_id, event_type, actor_user_id, ts, details_json) VALUES (?, ?, ?, ?, ?, ?)",
        (change_id, file_id, event_type, actor_id, timestamp, details)
    )