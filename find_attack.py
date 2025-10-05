# find_attack.py
import sqlite3
from pathlib import Path
from datetime import datetime, timedelta

def main():
    """
    Connects to the main app DB and actively searches for a valid
    exfiltration narrative sequence to verify the test data.
    """
    db_path = Path.home() / ".argus" / "argus.db"
    if not db_path.exists():
        print("ERROR: Application database not found.")
        return

    print(f"Connecting to {db_path}...")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    # Find all external share events
    share_events = conn.execute(
        "SELECT * FROM events WHERE event_type = 'file_shared_externally' ORDER BY ts DESC"
    ).fetchall()

    print(f"Found {len(share_events)} external share events. Searching for valid exfil patterns...")

    found_narrative = False
    time_window = timedelta(minutes=60) # Must match your config

    for share_event in share_events:
        # For each share, work backward
        file_id = share_event['file_id']
        actor_id = share_event['actor_user_id']
        share_time = datetime.fromisoformat(share_event['ts'])

        history = conn.execute(
            "SELECT * FROM events WHERE file_id = ? ORDER BY ts ASC", (file_id,)
        ).fetchall()

        if not history:
            continue

        creation_event = history[0]
        creation_time = datetime.fromisoformat(creation_event['ts'])

        if (share_time - creation_time) > time_window:
            continue # Too old

        # Check for the copy and rename stages
        was_copied = creation_event['event_type'] == 'file_copied'
        was_renamed = any(
            evt['event_type'] == 'file_renamed' and evt['actor_user_id'] == actor_id
            for evt in history
        )

        if was_copied and was_renamed:
            found_narrative = True
            print("\n" + "="*50)
            print(">>> SUCCESS: Found a valid exfiltration narrative!")
            print(f"    Final Share Event ID: {share_event['id']}")
            print(f"    File ID: {file_id}")
            print(f"    Actor: {actor_id}")
            print(f"    Sequence:")
            print(f"      - Copy:   Event ID {creation_event['id']} at {creation_event['ts']}")
            for evt in history:
                if evt['event_type'] == 'file_renamed' and evt['actor_user_id'] == actor_id:
                    print(f"      - Rename: Event ID {evt['id']} at {evt['ts']}")
                    break
            print(f"      - Share:  Event ID {share_event['id']} at {share_event['ts']}")
            print("="*50 + "\n")
            break # Stop after finding the first one

    if not found_narrative:
        print("\n>>> FAILURE: No valid exfiltration narrative sequence was found in the database.")
        print("The synthetic data does not contain the required test case.")

    conn.close()

if __name__ == "__main__":
    main()