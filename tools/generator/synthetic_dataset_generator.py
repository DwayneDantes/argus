# tools/generator/synthetic_dataset_generator.py
import logging
import random
import pandas as pd
import sqlite3
import sys

from .benign_fetcher import BenignFetcher
from .benign_simulator import BenignSimulator # <-- IMPORT THE NEW CLASS
from .scenarios import ScenarioInjector
from .schema import CANONICAL_EVENT_COLUMNS

class SyntheticDatasetGenerator:
    """
    Main class to generate a labeled dataset. It can either fetch a benign
    canvas from a real database OR simulate one from scratch, then inject
    synthetic attack sequences on top of it.
    """
    def __init__(self, config: dict, sqlite_path: str, seed: int, dry_run: bool = False):
        # ... (init method is unchanged)
        self.config = config
        self.sqlite_path = sqlite_path
        self.seed = seed
        self.dry_run = dry_run
        self.rng = random.Random(self.seed)
        self.logger = logging.getLogger(self.__class__.__name__)
        self.benign_events = []
        self.injected_events = []
        self.final_events_df = None
        self.attack_id_counter = 1

    def run(self, use_cache=False, force_refresh=False):
        """Execute the full dataset generation pipeline."""
        self.logger.info("Starting synthetic dataset generation pipeline...")
        self.logger.info(f"Random seed set to: {self.seed}")
        if self.dry_run:
            self.logger.warning("DRY RUN is enabled. No files will be written.")

        # --- MODIFIED SECTION: Choose between fetching and simulating ---
        if self.config.get('benign_simulation', {}).get('enabled', False):
            # The config enables simulation, so we use the simulator
            simulator = BenignSimulator(self.config, self.rng)
            self.benign_events = simulator.run()
        else:
            # Fallback to the original fetcher logic
            fetcher = BenignFetcher(self.config)
            self.benign_events = fetcher.fetch_or_load_benign_events(use_cache, force_refresh)
        # --- END OF MODIFIED SECTION ---

        # Add benign labels (this works for both fetched and simulated data)
        for event in self.benign_events:
            event['is_malicious'] = 0
            event['attack_scenario'] = None
            event['attack_role'] = 0
        self.logger.info(f"Loaded {len(self.benign_events)} benign events to serve as the canvas.")

        # Phase 2: Inject Malicious Scenarios
        injector = ScenarioInjector(self.config, self.benign_events, self.rng)
        self.injected_events, self.attack_id_counter = injector.run_injections(
            start_attack_id=self.attack_id_counter
        )
        self.logger.info(f"Generated {len(self.injected_events)} malicious events.")

        # Phase 3: Assemble, Sort, and Persist
        self._assemble_and_sort()
        self._persist_to_sqlite()
        self._print_summary_report()
        self.logger.info("Pipeline finished successfully.")
        self.logger.info(f"Final dataset is available at: {self.sqlite_path}")

    def _assemble_and_sort(self):
        # ... (this method is unchanged)
        self.logger.info("Assembling and sorting final event list...")
        combined_events = self.benign_events + self.injected_events
        if not combined_events:
            self.logger.warning("No events to process. Final dataset will be empty.")
            self.final_events_df = pd.DataFrame()
            return
        df = pd.DataFrame(combined_events)
        for col in CANONICAL_EVENT_COLUMNS:
            if col not in df.columns:
                df[col] = None
        self.final_events_df = df[CANONICAL_EVENT_COLUMNS]
        self.logger.info("Converting timestamps and sorting dataset chronologically...")
        self.final_events_df['timestamp'] = pd.to_datetime(self.final_events_df['timestamp'], errors='coerce')
        self.final_events_df.dropna(subset=['timestamp'], inplace=True)
        self.final_events_df.sort_values(by='timestamp', inplace=True)
        self.logger.info("Sorting complete.")

    def _persist_to_sqlite(self):
        # ... (this method is unchanged)
        if self.dry_run:
            self.logger.info(f"DRY RUN: Skipping write to SQLite file: {self.sqlite_path}")
            return
        if self.final_events_df.empty:
            self.logger.warning("DataFrame is empty, nothing to write.")
            return
        self.logger.info(f"Writing {len(self.final_events_df)} events to SQLite table 'events' in {self.sqlite_path}...")
        try:
            conn = sqlite3.connect(self.sqlite_path)
            self.final_events_df.to_sql(name='events', con=conn, if_exists='replace', index=False)
            self.logger.info("Successfully wrote to SQLite database.")
        except Exception as e:
            self.logger.error(f"Failed to write to SQLite database: {e}", exc_info=True)
            sys.exit(1)
        finally:
            if 'conn' in locals() and conn:
                conn.close()

    def _print_summary_report(self):
        # ... (this method is unchanged)
        malicious_count = self.final_events_df['is_malicious'].sum()
        total_count = len(self.final_events_df)
        benign_count = total_count - malicious_count
        self.logger.info("--- Generation Summary ---")
        print(f"  Total Benign Events: {benign_count}")
        print(f"  Total Injected Malicious Events: {malicious_count}")
        print(f"  Total Events in Dataset: {total_count}")
        if not self.final_events_df.empty:
            print(f"  Time Range: {self.final_events_df['timestamp'].min()} -> {self.final_events_df['timestamp'].max()}")
        print(f"  Output Path: {self.sqlite_path}")
        self.logger.info("--------------------------")