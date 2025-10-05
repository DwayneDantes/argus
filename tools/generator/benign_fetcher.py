# tools/generator/benign_fetcher.py
import logging
import sqlite3
import json
import os
from datetime import datetime, timedelta, timezone

class BenignFetcher:
    """
    Responsible for fetching and caching benign event data from the live
    Argus operational database. It performs the necessary JOINs and initial
    parsing to transform the normalized DB data into a denormalized, flat
    list of event dictionaries suitable for the generator.
    """
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        self.db_path = self.config['benign_source']['prod_db_path']
        self.cache_path = self.config['benign_source']['cache_path']
        self.days_to_fetch = self.config['benign_source']['days_to_fetch']

    def fetch_or_load_benign_events(self, use_cache=False, force_refresh=False):
        """
        Orchestrates fetching benign data.

        It follows a clear logic:
        1. If forcing a refresh, always fetch from the DB.
        2. If using cache and the cache file exists, load from it.
        3. Otherwise, fetch from the DB.
        4. After a successful DB fetch, save the results to the cache.
        """
        self.logger.info("Initiating benign data acquisition...")

        if not force_refresh and use_cache and os.path.exists(self.cache_path):
            return self._load_from_cache()

        benign_events = self._fetch_from_db()
        if benign_events:
            self._save_to_cache(benign_events)

        return benign_events

    def _fetch_from_db(self):
        """
        Connects to the operational SQLite database, executes the main JOIN
        query, and processes the results into the canonical event format.
        """
        if not os.path.exists(self.db_path):
            self.logger.error(f"Operational database not found at path: {self.db_path}")
            self.logger.error("Please ensure the path in generator_config.yaml is correct.")
            return []

        self.logger.info(f"Connecting to production database: {self.db_path}")
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            # Use sqlite3.Row to access columns by name (like a dictionary)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Calculate the start timestamp for the query window
            start_date = datetime.now(timezone.utc) - timedelta(days=self.days_to_fetch)
            start_date_iso = start_date.isoformat()

            query = """
                SELECT
                    e.drive_change_id AS event_id, e.ts AS timestamp,
                    e.event_type, e.details_json, u.email AS actor_email,
                    f.id AS file_id, f.name AS file_name, f.mime_type AS mime_type
                FROM events AS e
                LEFT JOIN users AS u ON e.actor_user_id = u.id
                LEFT JOIN files AS f ON e.file_id = f.id
                WHERE e.ts >= ?
                ORDER BY e.ts ASC;
            """
            self.logger.info(f"Fetching events from the last {self.days_to_fetch} days...")
            cursor.execute(query, (start_date_iso,))
            rows = cursor.fetchall()
            self.logger.info(f"Successfully fetched {len(rows)} raw event records from the database.")

            # Process rows into a list of dictionaries, enriching each one
            processed_events = [self._parse_and_enrich_event(dict(row)) for row in rows]
            return processed_events

        except sqlite3.Error as e:
            self.logger.error(f"Database error while fetching benign data: {e}", exc_info=True)
            return []
        finally:
            if conn:
                conn.close()
                self.logger.info("Database connection closed.")

    def _parse_and_enrich_event(self, event: dict) -> dict:
        """
        Parses the 'details_json' field to extract additional, optional fields
        and adds them to the event dictionary.
        """
        # Set defaults for fields that we will try to extract
        event['ip_address'] = None
        event['size_bytes'] = None

        if event.get('details_json'):
            try:
                details = json.loads(event['details_json'])
                # Assumption: IP address is nested this way based on Drive Activity API.
                # This might need adjustment based on your actual stored JSON structure.
                if 'primaryActionDetail' in details and details['primaryActionDetail']:
                    action_key = next(iter(details['primaryActionDetail'])) # e.g., 'edit', 'rename'
                    action_details = details['primaryActionDetail'][action_key]
                    # This is a hypothetical path, adjust if needed
                    event['ip_address'] = details.get('actors', [{}])[0].get('ipAddress')

            except (json.JSONDecodeError, TypeError, IndexError) as e:
                self.logger.debug(f"Could not parse details_json for event_id {event['event_id']}: {e}")

        return event

    def _load_from_cache(self):
        """Loads the benign event data from a local JSON cache file."""
        self.logger.info(f"Loading benign events from cache file: {self.cache_path}")
        try:
            with open(self.cache_path, 'r') as f:
                events = json.load(f)
            self.logger.info(f"Successfully loaded {len(events)} events from cache.")
            return events
        except (IOError, json.JSONDecodeError) as e:
            self.logger.error(f"Failed to load or parse cache file: {e}", exc_info=True)
            return []

    def _save_to_cache(self, events: list):
        """Saves the fetched benign event data to a local JSON cache file."""
        self.logger.info(f"Saving {len(events)} benign events to cache: {self.cache_path}")
        try:
            with open(self.cache_path, 'w') as f:
                json.dump(events, f, indent=2)
            self.logger.info("Cache file saved successfully.")
        except IOError as e:
            self.logger.error(f"Failed to write to cache file: {e}", exc_info=True)