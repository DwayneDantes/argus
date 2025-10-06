# tests/e2e_simulation.py (FINAL, CORRECTED, AND ROBUST)

import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

# We import the main orchestrator that we want to test
from app.analysis.ntw import get_final_threat_score

# We import the global state dictionaries so we can clear them before each test
from app.analysis.contextual_risk import ACTOR_WINDOWS
from app.analysis.narrative_builder import ACTIVE_FSMS

class TestEndToEndSimulation(unittest.TestCase):

    def setUp(self):
        """Clear all in-memory state before each test to ensure test isolation."""
        ACTOR_WINDOWS.clear()
        ACTIVE_FSMS.clear()

    # We patch each individual DAO function that is called within the entire analysis pipeline.
    # We patch them AT THEIR SOURCE ('app.db.dao') to guarantee interception.
    @patch('app.db.dao.get_file_vt_score')
    @patch('app.db.dao.get_user_baseline')
    @patch('app.db.dao.create_narrative')
    @patch('app.db.dao.get_db_connection')
    def test_e2e_stage_archive_exfil_detection(self, mock_get_db_connection, mock_create_narrative, mock_get_user_baseline, mock_get_file_vt_score):
        """
        Simulates a full 'stage_archive_exfil_v1' event stream, with all DAO calls mocked,
        and asserts that a critical, narrative-driven alert is generated ONLY on the final event.
        """
        # --- 1. Configure the Mocks ---
        # For the duration of this test, any call to these functions will return these values.
        
        # This prevents the TypeError.
        mock_get_file_vt_score.return_value = None 
        
        # This provides a default baseline for the off-hours check.
        mock_get_user_baseline.return_value = {
            'typical_activity_hours_json': '{"start": "08:00", "end": "18:00"}'
        }
        
        # These are needed for the 'with dao.get_db_connection()' block to work without a real DB.
        mock_get_db_connection.return_value.__enter__.return_value.cursor.return_value = "mock_cursor"
        
        # This handles the call when a narrative is successfully detected.
        mock_create_narrative.return_value = 1 

        # --- 2. Define the Event Stream ---
        actor = "e2e_tester@example.com"
        base_time = datetime.now(timezone.utc)
        
        event_stream = [
            # Step 1: Bulk Copy (simpler, just 2 events to prove the logic)
            {'id': 1000, 'ts': base_time, 'actor_user_id': actor, 'event_type': 'file_copied', 'name': 'doc_1.txt', 'mime_type': 'text/plain'},
            {'id': 1001, 'ts': base_time + timedelta(minutes=1), 'actor_user_id': actor, 'event_type': 'file_copied', 'name': 'doc_2.txt', 'mime_type': 'text/plain'},
            
            # Step 2: Archive Create
            {'id': 2000, 'ts': base_time + timedelta(minutes=5), 'actor_user_id': actor, 'event_type': 'file_created', 'name': 'archive.zip', 'mime_type': 'application/zip'},
            
            # Step 3: External Share (the final trigger)
            {'id': 3000, 'ts': base_time + timedelta(minutes=10), 'actor_user_id': actor, 'event_type': 'file_shared_externally', 'name': 'archive.zip', 'mime_type': 'application/zip'}
        ]

        # --- 3. Process the Stream and Test ---
        final_result = None
        for i, event in enumerate(event_stream):
            result = get_final_threat_score(event)
            
            # For all but the final event, assert the score is not Critical.
            if i < len(event_stream) - 1:
                self.assertNotEqual(result['threat_level'], 'Critical', f"A premature Critical alert was generated at step {i}")
            else:
                final_result = result

        # --- 4. Assert the Final Result ---
        self.assertIsNotNone(final_result, "Orchestrator did not produce a result for the final event.")
        self.assertIsNotNone(final_result.get('narrative_info'), "The completed narrative object is missing.")
        self.assertEqual(final_result['narrative_info']['narrative_type'], 'stage_archive_exfil_v1')
        self.assertEqual(final_result['breakdown']['logic_tier'], 'Narrative-Driven')
        self.assertEqual(final_result['threat_level'], 'Critical')
        self.assertGreaterEqual(final_result['final_score'], 70.0)