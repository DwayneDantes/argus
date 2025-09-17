from app.db import dao

def find_data_exfiltration_narratives():
    """
    Analyzes the event log to find sequences of events that match a known
    data exfiltration pattern.
    """
    print("\n--- Searching for Data Exfiltration Narratives ---")
    
    with dao.get_db_connection() as conn:
        cursor = conn.cursor()

        # This query finds all files that were EVER shared externally.
        # This is our list of "suspects".
        cursor.execute("""
            SELECT DISTINCT e.file_id, f.name FROM events e
            JOIN files f ON e.file_id = f.id
            WHERE e.event_type = 'file_shared_externally'
        """)
        suspect_files = cursor.fetchall()

        if not suspect_files:
            print("No externally shared files found. No potential narratives to analyze.")
            return

        print(f"Found {len(suspect_files)} externally shared files. Analyzing their history...")
        
        for file_row in suspect_files:
            file_id = file_row['file_id']
            file_name = file_row['name']
            
            # Now, for each suspect, get their full event history.
            cursor.execute("""
                SELECT event_type, ts FROM events
                WHERE file_id = ?
                ORDER BY ts ASC
            """, (file_id,))
            event_history = cursor.fetchall()

            # --- This is our Pattern Matching Logic ---
            event_types_in_history = [row['event_type'] for row in event_history]

            is_copied = 'file_copied' in event_types_in_history
            is_renamed = 'file_renamed' in event_types_in_history
            is_shared = 'file_shared_externally' in event_types_in_history

            # The "Stage, Obfuscate, Exfiltrate" Pattern
            if is_copied and is_renamed and is_shared:
                print("\n--------------------------------------------------")
                print(f"!!! HIGH-THREAT NARRATIVE DETECTED: Potential Data Exfiltration !!!")
                print(f"  - File: '{file_name}' (ID: {file_id})")
                print(f"  - Pattern: The file was first copied, then renamed, and finally shared externally.")
                print("  - Event Sequence:")
                for event in event_history:
                    print(f"    - {event['ts']}: {event['event_type']}")
                print("--------------------------------------------------")
    
    print("\n--- Narrative Search Complete ---")