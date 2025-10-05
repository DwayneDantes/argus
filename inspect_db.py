# inspect_db.py
import sqlite3
from pathlib import Path

db_path = Path(__file__).parent / "tools" / "argus_synthetic_dataset_v4.sqlite"

if not db_path.exists():
    print(f"ERROR: Database not found at '{db_path}'")
else:
    print(f"Inspecting tables in: {db_path}\n")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()
    conn.close()
    
    if not tables:
        print("No tables found in the database.")
    else:
        print("Tables found:")
        for table in tables:
            print(f"  - {table[0]}")