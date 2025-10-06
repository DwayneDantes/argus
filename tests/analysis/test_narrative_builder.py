# In tests/analysis/test_narrative_builder.py

import unittest
import time
from datetime import datetime, timedelta
# Import the main function and the state dictionary for inspection/clearing
from app.analysis.narrative_builder import analyze_narratives_for_actor, ACTIVE_FSMS, NARRATIVE_TEMPLATES

class TestNarrativeBuilder(unittest.TestCase):

    def setUp(self):
        """Clear the FSM state dictionary before each test to ensure isolation."""
        ACTIVE_FSMS.clear()
        # Make a copy of the original templates to restore after tests
        self.original_templates = {k: v.copy() for k, v in NARRATIVE_TEMPLATES.items()}

    def tearDown(self):
        """Restore original templates after tests that modify them."""
        NARRATIVE_TEMPLATES.clear()
        NARRATIVE_TEMPLATES.update(self.original_templates)

    def test_fsm_completes_on_correct_sequence(self):
        """Tests that a narrative is detected when micro-patterns arrive in the correct order."""
        actor = "test_user@example.com"
        
        # Define a simpler narrative for this test
        NARRATIVE_TEMPLATES['test_narrative'] = {
            "id": "test_narrative", "starter_patterns": ["pattern_A"],
            "ordered_steps": [{'type': 'pattern_A'}, {'type': 'pattern_B'}],
            "total_time_window_minutes": 5, "base_score": 50.0, "reason": "Test"
        }

        # Step 1: A starter pattern arrives. This should instantiate an FSM.
        result1 = analyze_narratives_for_actor(actor, {'pattern_A': {'data': 'value1'}})
        self.assertIsNone(result1)
        self.assertEqual(len(ACTIVE_FSMS[actor]), 1)
        self.assertEqual(ACTIVE_FSMS[actor][0].state, 1)
        
        # Step 2: The next correct pattern arrives. The FSM should complete.
        result2 = analyze_narratives_for_actor(actor, {'pattern_B': {'data': 'value2'}})
        self.assertIsNotNone(result2)
        self.assertEqual(result2['narrative_type'], 'test_narrative')
        self.assertIn('pattern_A', result2['evidence'])
        self.assertIn('pattern_B', result2['evidence'])

        # After completion, the FSM should be removed
        self.assertEqual(len(ACTIVE_FSMS[actor]), 0)

    def test_fsm_does_not_start_on_non_starter_pattern(self):
        """Tests that an FSM is not created for a pattern not in 'starter_patterns'."""
        actor = "test_user@example.com"
        NARRATIVE_TEMPLATES['test_narrative'] = {
            "id": "test_narrative", "starter_patterns": ["pattern_A"],
            "ordered_steps": [{'type': 'pattern_A'}, {'type': 'pattern_B'}],
            "total_time_window_minutes": 5, "base_score": 50.0, "reason": "Test"
        }
        
        # A non-starter pattern arrives first.
        analyze_narratives_for_actor(actor, {'pattern_B': {'data': 'value'}})
        self.assertEqual(len(ACTIVE_FSMS[actor]), 0)

    def test_fsm_expires_over_time(self):
        """Tests that an FSM is correctly pruned if it becomes too old."""
        actor = "test_user@example.com"
        # Set a very short expiration time for the test
        NARRATIVE_TEMPLATES['stage_archive_exfil_v1']['total_time_window_minutes'] = 0.01 # ~0.6 seconds

        # Start the FSM with a bulk_copy
        analyze_narratives_for_actor(actor, {'bulk_copy': {'count': 20}})
        self.assertEqual(len(ACTIVE_FSMS[actor]), 1)
        
        # Wait for longer than the expiration window
        time.sleep(1) 
        
        # Send another pattern. The first action should be to prune the expired FSM.
        analyze_narratives_for_actor(actor, {}) # Send empty patterns to trigger pruning
        self.assertEqual(len(ACTIVE_FSMS[actor]), 0, "Expired FSM should have been pruned.")