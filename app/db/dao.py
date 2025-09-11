# app/db/dao.py

import sqlite3
from pathlib import Path
import sys # Import the sys module to exit gracefully

# Use the same hidden .argus directory we created in Phase 1
APP_DIR = Path.home() / ".argus"
DB_FILE = APP_DIR / "argus.db"
SCHEMA_FILE = Path(__file__).parent / "schema.sql"

def get_db_connection() -> sqlite3.Connection:
    """Establishes a connection to the SQLite database."""
    APP_DIR.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_FILE, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    return conn

# --- DIAGNOSTIC VERSION of initialize_database ---
def initialize_database():
    """
    Creates the database and tables from the schema if they don't exist.
    This version includes diagnostic print statements.
    """
    print("\n--- Running Database Initialization ---")
    
    # 1. Check if the schema file exists where we expect it.
    print(f"Looking for schema file at: {SCHEMA_FILE.resolve()}")
    if not SCHEMA_FILE.exists():
        print("!!! CRITICAL ERROR: schema.sql not found at the expected location.")
        print("Please ensure 'schema.sql' is in the same directory as 'dao.py'.")
        sys.exit(1) # Stop the program immediately
    else:
        print("Schema file found successfully.")

    # 2. Try to read the schema file.
    try:
        with open(SCHEMA_FILE, 'r') as f:
            schema_script = f.read()
        
        if not schema_script.strip():
            print("!!! CRITICAL ERROR: schema.sql appears to be empty.")
            sys.exit(1)
        else:
            # Print the first few characters to confirm it's not empty
            print(f"Schema content loaded (first 60 chars): {schema_script.strip()[:60]}...")
            
    except Exception as e:
        print(f"!!! CRITICAL ERROR: Failed to read schema.sql file: {e}")
        sys.exit(1)

    # 3. Execute the schema script.
    try:
        with get_db_connection() as conn:
            print(f"Executing schema on database: {DB_FILE.resolve()}")
            conn.executescript(schema_script)
            conn.commit()
        print("Database schema executed successfully.")
    except Exception as e:
        print(f"!!! CRITICAL ERROR: An error occurred during schema execution: {e}")
        sys.exit(1)
        
    print("--- Database Initialization Complete ---\n")


def get_meta_value(key: str) -> str | None:
    """Retrieves a value from the meta table."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM meta WHERE key = ?", (key,))
        row = cursor.fetchone()
        return row['value'] if row else None

def set_meta_value(key: str, value: str):
    """Inserts or updates a value in the meta table."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, value))
        conn.commit()