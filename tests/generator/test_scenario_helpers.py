# In tests/generator/test_scenario_helpers.py

import unittest
from datetime import datetime
import random
# You will need to import your ScenarioInjector and create_event_from_template
from tools.generator.scenarios import ScenarioInjector
from tools.generator.utils import create_event_from_template 

# Mock the create_event_from_template to isolate the test
# Or ensure your test has access to it. For now, we assume it's imported.

class TestScenarioHelpers(unittest.TestCase):

    def setUp(self):
        """Set up a dummy injector and some mock benign data for testing."""
        # A minimal config needed for the injector
        config = {'scenarios': {}} 
        # A simple list of benign events to act as templates
        self.mock_benign_events = [
            {'event_id': 'evt_1', 'timestamp': '2025-09-01T10:00:00Z', 'actor_email': 'test@example.com', 'file_id': 'file_A'}
        ]
        self.injector = ScenarioInjector(config, self.mock_benign_events, random.Random(42))

    def test_generate_bulk_events_counts_and_consistency(self):
        """
        Tests that the helper generates the correct number of events
        and that all events share the same attack_id.
        """
        actor = "attacker@internal.com"
        event_type = "file_copied"
        num_events = 25
        base_time = datetime.fromisoformat("2025-09-10T12:00:00+00:00")
        window_minutes = 30
        attack_id = "exfil_test_001"
        attack_role = 2

        generated_events = self.injector._generate_bulk_events(
            actor, event_type, num_events, base_time, window_minutes,
            self.mock_benign_events, attack_id, attack_role
        )

        # Assertion 1: Verify the number of generated events is correct.
        self.assertEqual(len(generated_events), num_events)

        # Assertion 2: Verify all events have the correct and consistent attack_id.
        all_ids_match = all(evt['attack_scenario'] == attack_id for evt in generated_events)
        self.assertTrue(all_ids_match, "Not all generated events had the correct attack_id")
        
        # Assertion 3: Verify all events have the correct actor
        all_actors_match = all(evt['actor_email'] == actor for evt in generated_events)
        self.assertTrue(all_actors_match, "Not all generated events had the correct actor")


        if __name__ == '__main__':
            unittest.main()

    def test_generate_archive_create_mime_and_name(self):
        """
        Tests that the archive helper correctly sets the filename, MIME type,
        and event type for a new archive creation event.
        """
        actor = "attacker@internal.com"
        archive_name = "secret_project_files.zip"
        base_time = datetime.fromisoformat("2025-09-10T12:30:00+00:00")
        attack_id = "exfil_test_001"
        attack_role = 2

        generated_event = self.injector._generate_archive_create(
            actor, base_time, archive_name, self.mock_benign_events,
            attack_id, attack_role
        )

        # Assertion 1: Verify the event type is 'file_created'.
        self.assertEqual(generated_event['event_type'], 'file_created')

        # Assertion 2: Verify the filename is set correctly.
        self.assertEqual(generated_event['file_name'], archive_name)

        # Assertion 3: Verify the MIME type is correctly set to 'application/zip'.
        self.assertEqual(generated_event['mime_type'], 'application/zip')
        
        # Assertion 4: Verify it's a new file ID and not from the template
        self.assertNotEqual(generated_event['file_id'], self.mock_benign_events[0]['file_id'])

    def test_generate_folder_move(self):
        """Tests that the folder move helper sets the correct event type and file ID."""
        actor = "attacker@internal.com"
        file_to_move = "file_to_be_moved_id"
        base_time = datetime.fromisoformat("2025-09-10T12:40:00+00:00")
        attack_id = "exfil_test_001"
        
        generated_event = self.injector._generate_folder_move(
            actor, base_time, file_to_move, "staging_folder", 
            self.mock_benign_events, attack_id, 2
        )
        
        self.assertEqual(generated_event['event_type'], 'file_moved')
        self.assertEqual(generated_event['file_id'], file_to_move)

    def test_generate_external_share(self):
        """Tests that the external share helper works for public links."""
        actor = "attacker@internal.com"
        file_to_share = "file_to_be_shared_id"
        base_time = datetime.fromisoformat("2025-09-10T12:50:00+00:00")
        attack_id = "exfil_test_001"
        
        generated_event = self.injector._generate_external_share(
            actor, base_time, file_to_share, "public", 
            self.mock_benign_events, attack_id, 1
        )
        
        self.assertEqual(generated_event['event_type'], 'file_shared_externally')
        self.assertEqual(generated_event['file_id'], file_to_share)
        self.assertIn("anyoneWithLink", generated_event['details_json'])