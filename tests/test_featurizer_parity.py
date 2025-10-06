# In tests/test_featurizer_parity.py (FULL IMPLEMENTATION for Milestone 3.1)

import unittest
import pandas as pd
from datetime import datetime, timedelta

# Import both the batch and the live functions
from ml_utils.feature_engineering import generate_feature_matrix
from app.analysis.contextual_risk import update_and_compute_micro_patterns, ACTOR_WINDOWS

class TestFeaturizerParity(unittest.TestCase):

    def setUp(self):
        """Clear the live aggregator's state before each test."""
        ACTOR_WINDOWS.clear()

    def test_live_vs_batch_parity(self):
        """
        Ensures the live, incremental aggregator produces the exact same feature values
        as the batch feature engineering pipeline for a given event stream.
        """
        base_time = datetime.fromisoformat('2025-10-01T12:00:00+00:00')
        events_list = [
            {'id': 1, 'timestamp': base_time, 'actor_email': 'user_a', 'event_type': 'file_copied', 'mime_type': 'text/plain'},
            {'id': 2, 'timestamp': base_time + timedelta(minutes=1), 'actor_email': 'user_a', 'event_type': 'file_copied', 'mime_type': 'text/plain'},
            {'id': 3, 'timestamp': base_time + timedelta(minutes=2), 'actor_email': 'user_b', 'event_type': 'file_trashed', 'mime_type': 'image/jpeg'},
            {'id': 4, 'timestamp': base_time + timedelta(minutes=3), 'actor_email': 'user_a', 'event_type': 'file_trashed', 'mime_type': 'text/plain'},
            {'id': 5, 'timestamp': base_time + timedelta(minutes=35), 'actor_email': 'user_a', 'event_type': 'file_copied', 'mime_type': 'text/plain'},
        ]
        # Add keys needed for the live simulation
        for e in events_list:
            e['ts'] = e['timestamp']
            e['actor_user_id'] = e['actor_email']

        events_df = pd.DataFrame(events_list)

        # 2. Run the BATCH process
        batch_features_df = generate_feature_matrix(events_df.copy())

        # 3. Run the LIVE process, event by event
        live_features_list = []
        for event in events_list:
            live_features = update_and_compute_micro_patterns(event)
            live_features_list.append(live_features)
        live_features_df = pd.DataFrame(live_features_list)

        # 4. ASSERT PARITY for a key micro-pattern
        feature_to_test = 'actor_copy_count_30m'

        # The batch process already includes the .shift(1) logic.
        batch_output = batch_features_df[feature_to_test].tolist()
        
        # The live process is designed to do the same.
        live_output = live_features_df[feature_to_test].tolist()
        
        # Expected values based on the event stream:
        # Event 1 (user_a): 0.0 (no history)
        # Event 2 (user_a): 1.0 (sees event 1)
        # Event 3 (user_b): 0.0 (different user, no history)
        # Event 4 (user_a): 2.0 (sees events 1 and 2)
        # Event 5 (user_a): 1.0 (sees event 4, but events 1 & 2 are now > 30 mins old)
        expected_values = [0.0, 1.0, 0.0, 2.0, 0.0]

        self.assertListEqual(batch_output, expected_values, "Batch featurizer output is incorrect.")
        self.assertListEqual(live_output, expected_values, "Live aggregator output is incorrect.")
        
        # Final and most important assertion
        self.assertListEqual(
            batch_output, live_output,
            "PARITY CHECK FAILED! The live aggregator and batch featurizer are not identical."
        )