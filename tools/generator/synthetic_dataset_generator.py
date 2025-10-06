# tools/generator/synthetic_dataset_generator.py (FINAL CORRECTED VERSION)

import logging
import random
import pandas as pd
import sqlite3
import sys

from .benign_fetcher import BenignFetcher
from .benign_simulator import BenignSimulator
from .scenarios import ScenarioInjector
from .schema import CANONICAL_EVENT_COLUMNS

class SyntheticDatasetGenerator:
    """
    Main class to generate a labeled dataset. It orchestrates the creation
    of a benign canvas, injects benign mimics, and then injects malicious
    attack sequences.
    """
    def __init__(self, config: dict, sqlite_path: str, seed: int, dry_run: bool = False):
        self.config = config
        self.sqlite_path = sqlite_path
        self.seed = seed
        self.dry_run = dry_run
        self.rng = random.Random(self.seed)
        self.logger = logging.getLogger(self.__class__.__name__)
        self.benign_events = []
        self.injected_malicious_events = [] # Use a separate list for clarity
        self.final_events_df = None
        self.attack_id_counter = 1

    def run(self, use_cache=False, force_refresh=False):
        """Execute the full dataset generation pipeline."""
        self.logger.info("Starting synthetic dataset generation pipeline...")
        self.logger.info(f"Random seed set to: {self.seed}")
        if self.dry_run:
            self.logger.warning("DRY RUN is enabled. No files will be written.")

        # --- Phase 1: Create the Benign Canvas ---
        if self.config.get('benign_simulation', {}).get('enabled', False):
            simulator = BenignSimulator(self.config, self.rng)
            self.benign_events = simulator.run()
        else:
            fetcher = BenignFetcher(self.config)
            self.benign_events = fetcher.fetch_or_load_benign_events(use_cache, force_refresh)

        # Add default benign labels
        for event in self.benign_events:
            event['is_malicious'] = 0
            event['attack_scenario'] = None
            event['attack_role'] = 0
        self.logger.info(f"Loaded {len(self.benign_events)} base benign events to serve as the canvas.")

        # --- Phase 1.5: Inject Benign Mimics ---
        self._inject_benign_mimics()

        # --- Phase 2: Inject Malicious Scenarios ---
        injector = ScenarioInjector(self.config, self.benign_events, self.rng)
        self.injected_malicious_events, self.attack_id_counter = injector.run_injections()
        self.logger.info(f"Generated {len(self.injected_malicious_events)} malicious events.")

        # --- Phase 3: Assemble, Sort, and Persist ---
        self._assemble_and_sort()
        self._persist_to_sqlite()
        self._print_summary_report()
        self.logger.info("Pipeline finished successfully.")
        self.logger.info(f"Final dataset is available at: {self.sqlite_path}")
    
    def _inject_benign_mimics(self):
        """
        Orchestrates the injection of 'hard negative' scenarios that resemble attacks but are benign.
        """
        self.logger.info("Injecting benign mimic scenarios to harden the dataset...")
        
        injector = ScenarioInjector(self.config, self.benign_events, self.rng)
        
        mimic_configs = self.config.get('benign_mimics', {})
        if mimic_configs.get('project_decommissioning', {}).get('enabled', False):
            count = mimic_configs['project_decommissioning'].get('count', 0)
            mimic_events = injector.inject_project_decommissioning(num_trials=count)
            # Add the generated events to the main benign list
            self.benign_events.extend(mimic_events)
            self.logger.info(f"Injected {len(mimic_events)} 'Project Decommissioning' benign mimic events.")

    def _assemble_and_sort(self):
        """Combines all events, ensures schema conformity, and sorts chronologically."""
        self.logger.info("Assembling and sorting final event list...")
        combined_events = self.benign_events + self.injected_malicious_events
        
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
        """Writes the final DataFrame to a SQLite database file."""
        if self.dry_run:
            self.logger.info(f"DRY RUN: Skipping write to SQLite file: {self.sqlite_path}")
            return
        if self.final_events_df is None or self.final_events_df.empty:
            self.logger.warning("DataFrame is empty, nothing to write to SQLite.")
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
        """Prints a final, correctly grouped summary of the generated dataset."""
        if self.final_events_df is None or self.final_events_df.empty:
            self.logger.warning("Cannot generate summary report; DataFrame is empty.")
            return

        total_count = len(self.final_events_df)
        malicious_count = self.final_events_df['is_malicious'].sum()
        benign_count = total_count - malicious_count
        
        self.logger.info("--- Generation Summary ---")
        print(f"  Total Events in Dataset: {total_count}")
        print(f"    - Benign Events:         {benign_count}")
        print(f"    - Malicious Events:      {malicious_count}")

        if total_count > 0:
            malicious_fraction = (malicious_count / total_count) * 100
            print(f"  Malicious Fraction:        {malicious_fraction:.2f}%")
        
        if not self.final_events_df.empty:
            print(f"  Time Range: {self.final_events_df['timestamp'].min()} -> {self.final_events_df['timestamp'].max()}")
        
        print("\n  Breakdown by Scenario Type:")
        
        # FIX: Create a temporary column with just the narrative type, stripping the trial number
        df_copy = self.final_events_df.copy()
        
        # This regex splits the string by the last underscore and takes everything before it.
        # It handles names like 'stage_archive_exfil_v1_1' -> 'stage_archive_exfil_v1'
        df_copy['scenario_type'] = df_copy['attack_scenario'].str.replace(r'_\d+$', '', regex=True)
        
        # Handle the benign events which have a None value
        # We can group the original canvas and our mimics together for a clean report
        def classify_benign(scenario):
            if pd.isna(scenario):
                return "Benign (Original Canvas)"
            if "benign_mimic" in scenario:
                return "Benign Mimic (All Types)"
            return scenario

        df_copy['scenario_type'] = df_copy['scenario_type'].apply(classify_benign)
        
        scenario_counts = df_copy['scenario_type'].value_counts()
        
        for scenario, count in scenario_counts.items():
            print(f"    - {scenario}: {count} events")

        print(f"\n  Output Path: {self.sqlite_path}")
        self.logger.info("--------------------------")