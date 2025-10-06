# In tests/generator/test_narrative_injection.py

import unittest
from collections import defaultdict
import random
from tools.generator.scenarios import ScenarioInjector

class TestNarrativeInjection(unittest.TestCase):

    def setUp(self):
        """Set up a dummy injector and some mock benign data."""
        config = {'scenarios': {}} 
        # Create a slightly larger pool of mock events for the injector to use
        self.mock_benign_events = [
            {'event_id': f'evt_{i}', 'timestamp': f'2025-09-01T10:{i:02d}:00Z', 
             'actor_email': 'test@example.com', 'file_id': f'file_{i}'}
            for i in range(50)
        ]
        self.injector = ScenarioInjector(config, self.mock_benign_events, random.Random(42))

    def test_stage_archive_exfil_v1_is_detectable(self):
        """
        Tests that a full injection of the exfil narrative produces a
        chronologically correct and logically consistent sequence of events.
        """
        # 1. RUN: Execute the injection for a single trial
        self.injector.inject_stage_archive_exfil_v1(num_trials=1)
        injected_events = self.injector.injected_events
        
        # We expect at least 4 steps + the bulk copies
        self.assertGreaterEqual(len(injected_events), 4) 

        # 2. SCAN: Group the injected events by their attack_id
        events_by_narrative = defaultdict(list)
        for evt in injected_events:
            events_by_narrative[evt['attack_scenario']].append(evt)
        
        # 3. VERIFY: Check the contents of our injected narrative
        narrative_id = "stage_archive_exfil_v1_1" # Based on our counter's logic
        self.assertIn(narrative_id, events_by_narrative)
        
        narrative_events = sorted(events_by_narrative[narrative_id], key=lambda x: x['timestamp'])

        # Create a simple list of the event types in chronological order
        event_type_sequence = [evt['event_type'] for evt in narrative_events]

        # Assert that the core sequence exists. We check for the last 3 steps as they are unique.
        # The 'file_copied' events will be mixed in at the start.
        expected_final_sequence = ['file_created', 'file_moved', 'file_shared_externally']
        
        # Find the index of the archive creation
        try:
            archive_create_index = event_type_sequence.index('file_created')
        except ValueError:
            self.fail("Narrative is missing the 'file_created' (archive) step.")

        # Check the sequence from that point forward
        self.assertEqual(
            event_type_sequence[archive_create_index:], 
            expected_final_sequence,
            "The final steps of the narrative are out of order or missing."
        )

        # Verify the archive file ID is consistent
        archive_event = next(e for e in narrative_events if e['event_type'] == 'file_created')
        archive_file_id = archive_event['file_id']
        
        move_event = next(e for e in narrative_events if e['event_type'] == 'file_moved')
        share_event = next(e for e in narrative_events if e['event_type'] == 'file_shared_externally')
        
        self.assertEqual(move_event['file_id'], archive_file_id)
        self.assertEqual(share_event['file_id'], archive_file_id)