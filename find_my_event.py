# find_my_event.py
import sqlite3
from pathlib import Path

db_path = Path.home() / ".argus" / "argus.db"
if not db_path.exists():
    print("ERROR: Database not found.")
else:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    # Find the most recent 'file_shared_externally' event
    event = conn.execute(
        "SELECT id, file_id, ts FROM events WHERE event_type = 'file_shared_externally' ORDER BY ts DESC LIMIT 1"
    ).fetchone()
    conn.close()
    
    if event:
        print("\n" + "="*50)
        print(">>> Found the target event from your live test!")
        print(f"    EVENT ID TO USE: {event['id']}")
        print(f"    File ID: {event['file_id']}")
        print(f"    Timestamp: {event['ts']}")
        print("="*50 + "\n")
    else:
        print("\n>>> No external share event was found. Please re-run '--ingest-once'.")