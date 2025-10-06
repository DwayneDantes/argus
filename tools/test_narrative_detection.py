# tools/test_narrative_detection.py
"""
Test script to verify narrative detection is working.
This creates synthetic events that should trigger the narrative detector.
"""

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys

# Add the parent directory to the path so we can import app modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.db import dao
from app.analysis.ntw import get_final_threat_score

def create_test_events():
    """Creates a sequence of events that should trigger the exfiltration narrative."""
    
    print("\n=== Creating Test Events for Narrative Detection ===\n")
    
    with dao.get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Test user and file
        test_user_id = "test_narrative_user_123"
        test_file_prefix = "narrative_test_file"
        
        # Clean up any previous test data
        cursor.execute("DELETE FROM events WHERE actor_user_id = ?", (test_user_id,))
        cursor.execute("DELETE FROM files WHERE id LIKE ?", (f"{test_file_prefix}%",))
        cursor.execute("DELETE FROM users WHERE id = ?", (test_user_id,))
        conn.commit()
        
        # Create test user
        cursor.execute(
            "INSERT INTO users (id, display_name, email) VALUES (?, ?, ?)",
            (test_user_id, "Test Narrative User", "test@example.com")
        )
        
        base_time = datetime.now(timezone.utc)
        
        # Step 1: Create multiple copy events (should trigger bulk_copy micro-pattern)
        print("Step 1: Creating bulk copy events...")
        for i in range(3):
            file_id = f"{test_file_prefix}_copy_{i}"
            file_name = f"sensitive_data_{i}.xlsx"
            
            # Create file
            cursor.execute(
                """INSERT INTO files (id, name, mime_type, created_time, modified_time, trashed, parents_json, md5Checksum)
                   VALUES (?, ?, ?, ?, ?, 0, '[]', ?)""",
                (file_id, file_name, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                 base_time.isoformat(), base_time.isoformat(), f"md5_copy_{i}")
            )
            
            # Create copy event
            event_time = base_time + timedelta(seconds=i*10)
            cursor.execute(
                """INSERT INTO events (drive_change_id, file_id, event_type, actor_user_id, ts, details_json, is_analyzed)
                   VALUES (?, ?, 'file_copied', ?, ?, '{}', 0)""",
                (f"test_copy_{i}", file_id, test_user_id, event_time.isoformat())
            )
            print(f"  ✓ Created copy event {i+1}/3")
        
        # Step 2: Create archive event (should trigger archive_create micro-pattern)
        print("\nStep 2: Creating archive creation event...")
        archive_file_id = f"{test_file_prefix}_archive"
        archive_time = base_time + timedelta(minutes=5)
        
        cursor.execute(
            """INSERT INTO files (id, name, mime_type, created_time, modified_time, trashed, parents_json, md5Checksum)
               VALUES (?, ?, 'application/zip', ?, ?, 0, '[]', ?)""",
            (archive_file_id, "company_data.zip", archive_time.isoformat(), 
             archive_time.isoformat(), "md5_archive")
        )
        
        cursor.execute(
            """INSERT INTO events (drive_change_id, file_id, event_type, actor_user_id, ts, details_json, is_analyzed)
               VALUES (?, ?, 'file_created', ?, ?, '{}', 0)""",
            (f"test_archive", archive_file_id, test_user_id, archive_time.isoformat())
        )
        print("  ✓ Created archive event")
        
        # Step 3: Create external share event (should trigger external_share and complete narrative)
        print("\nStep 3: Creating external share event...")
        share_time = base_time + timedelta(minutes=10)
        
        cursor.execute(
            """UPDATE files SET is_shared_externally = 1 WHERE id = ?""",
            (archive_file_id,)
        )
        
        cursor.execute(
            """INSERT INTO events (drive_change_id, file_id, event_type, actor_user_id, ts, details_json, is_analyzed)
               VALUES (?, ?, 'file_shared_externally', ?, ?, '{}', 0)""",
            (f"test_share", archive_file_id, test_user_id, share_time.isoformat())
        )
        print("  ✓ Created external share event")
        
        conn.commit()
        
    print("\n=== Test Events Created Successfully ===")
    print(f"\nTest user ID: {test_user_id}")
    print("Events created: 3 copies + 1 archive creation + 1 external share")
    print("\nNow run: python main.py --scan-everything")
    print("This should detect the narrative pattern!\n")

def check_narrative_results():
    """Checks if any narratives were detected."""
    
    print("\n=== Checking Narrative Detection Results ===\n")
    
    with dao.get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Check for narratives
        cursor.execute("SELECT COUNT(*) as count FROM narratives")
        narrative_count = cursor.fetchone()['count']
        
        print(f"Total narratives detected: {narrative_count}")
        
        if narrative_count > 0:
            cursor.execute("""
                SELECT narrative_id, narrative_type, primary_actor_id, 
                       start_time, end_time, final_score
                FROM narratives
                ORDER BY narrative_id DESC
                LIMIT 5
            """)
            
            print("\nRecent narratives:")
            print("-" * 80)
            for row in cursor.fetchall():
                print(f"ID: {row['narrative_id']}")
                print(f"  Type: {row['narrative_type']}")
                print(f"  Actor: {row['primary_actor_id']}")
                print(f"  Score: {row['final_score']}")
                print(f"  Time: {row['start_time']} → {row['end_time']}")
                
                # Get linked events
                cursor.execute("""
                    SELECT COUNT(*) as event_count 
                    FROM narrative_events 
                    WHERE narrative_id = ?
                """, (row['narrative_id'],))
                event_count = cursor.fetchone()['event_count']
                print(f"  Linked events: {event_count}")
                print("-" * 80)
        else:
            print("\n⚠️  No narratives detected yet.")
            print("Try running: python main.py --scan-everything")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Test narrative detection system")
    parser.add_argument("--create", action="store_true", help="Create test events")
    parser.add_argument("--check", action="store_true", help="Check for detected narratives")
    
    args = parser.parse_args()
    
    if args.create:
        create_test_events()
    elif args.check:
        check_narrative_results()
    else:
        print("Usage:")
        print("  python tools/test_narrative_detection.py --create   # Create test events")
        print("  python tools/test_narrative_detection.py --check    # Check results")