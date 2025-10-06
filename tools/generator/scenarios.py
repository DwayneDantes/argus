# tools/generator/scenarios.py (FINAL INTEGRATED VERSION)

import logging
import random
import uuid
import string
from datetime import datetime, timedelta
from collections import Counter
from .utils import create_event_from_template, get_random_time_offset

class ScenarioInjector:
    """
    Contains the logic for injecting all defined malicious scenarios using a
    modular, narrative-centric approach.
    """
    def __init__(self, config, benign_events, rng: random.Random):
        self.config = config
        self.benign_events = benign_events
        self.rng = rng
        self.logger = logging.getLogger(self.__class__.__name__)
        self.injected_events = []
        self.attack_id_counter = 1 # Start counter at 1 for clearer IDs

    def run_injections(self):
        """
        Runs all enabled scenario injectors based on the configuration.
        This is the central dispatcher for all narrative types.
        """
        self.logger.info("Starting injection of malicious scenarios...")

        if not self.benign_events:
            self.logger.warning("Benign event canvas is empty. Skipping all injections.")
            return [], self.attack_id_counter

        scenario_configs = self.config.get('scenarios', {})

        if scenario_configs.get('stage_archive_exfil_v1', {}).get('enabled', False):
            count = scenario_configs['stage_archive_exfil_v1'].get('count', 0)
            self.inject_stage_archive_exfil_v1(count)

        if scenario_configs.get('mass_deletion', {}).get('enabled', False):
            count = scenario_configs['mass_deletion'].get('count', 0)
            self.inject_mass_deletion_v2(count)

        if scenario_configs.get('ransomware', {}).get('enabled', False):
            count = scenario_configs['ransomware'].get('count', 0)
            self.inject_ransomware_v2(count)

        return self.injected_events, self.attack_id_counter

    # ===================================================================
    # == NARRATIVE 1: Stage, Archive, and Exfiltrate (NEW & MODULAR)
    # ===================================================================
    def inject_stage_archive_exfil_v1(self, num_trials: int):
        """Injects the 'stage_archive_exfil_v1' compound narrative N times."""
        if num_trials == 0: return
        self.logger.info(f"Injecting {num_trials} trials of 'stage_archive_exfil_v1' narrative...")
        
        for i in range(num_trials):
            attack_id = f"stage_archive_exfil_v1_{self.attack_id_counter + i}"
            actor_email = self.rng.choice([e['actor_email'] for e in self.benign_events if e['actor_email']])
            actor_events = [e for e in self.benign_events if e['actor_email'] == actor_email]
            if not actor_events: continue
            base_event = self.rng.choice(actor_events)
            t0 = datetime.fromisoformat(base_event['timestamp'])
            
            t1 = t0 + get_random_time_offset(mean_seconds=300, sigma=0.8, rng=self.rng)
            num_files_to_copy = self.rng.randint(10, 40)
            bulk_copy_events = self._generate_bulk_events(
                actor_email, 'file_copied', num_files_to_copy, t1, 20, actor_events, attack_id, 2)
            self.injected_events.extend(bulk_copy_events)

            t2_base = max(datetime.fromisoformat(evt['timestamp']) for evt in bulk_copy_events)
            t2 = t2_base + get_random_time_offset(mean_seconds=600, sigma=0.7, rng=self.rng)
            archive_name = f"Project_Backup_{uuid.uuid4().hex[:6]}.zip"
            archive_event = self._generate_archive_create(
                actor_email, t2, archive_name, actor_events, attack_id, 2)
            self.injected_events.append(archive_event)
            archive_file_id = archive_event['file_id']

            t3 = t2 + get_random_time_offset(mean_seconds=120, sigma=0.5, rng=self.rng)
            move_event = self._generate_folder_move(
                actor_email, t3, archive_file_id, "Temp_Share", actor_events, attack_id, 2)
            self.injected_events.append(move_event)

            t4 = t3 + get_random_time_offset(mean_seconds=120, sigma=0.5, rng=self.rng)
            share_event = self._generate_external_share(
                actor_email, t4, archive_file_id, 'public', actor_events, attack_id, 1)
            self.injected_events.append(share_event)
        self.attack_id_counter += num_trials

    # ===================================================================
    # == NARRATIVE 2: Mass Deletion (REFACTORED)
    # ===================================================================
    def inject_mass_deletion_v2(self, count: int):
        """Injects mass deletion scenarios N times using the new helper."""
        if count == 0: return
        self.logger.info(f"Injecting {count} Mass Deletion scenarios...")

        user_activity = Counter(event['actor_email'] for event in self.benign_events if event['actor_email'])
        top_actors = [user for user, count in user_activity.most_common(10)]
        if not top_actors: return
        
        for i in range(count):
            attack_id = f"mass_deletion_v2_{self.attack_id_counter + i}"
            actor_email = self.rng.choice(top_actors)
            base_time = datetime.fromisoformat(self.rng.choice(self.benign_events)['timestamp'])
            num_files_to_trash = self.rng.randint(30, 150)

            # Use the new helper for consistency
            trash_events = self._generate_bulk_events(
                actor_email, 'file_trashed', num_files_to_trash, base_time, 60, 
                self.benign_events, attack_id, 1
            )
            self.injected_events.extend(trash_events)
        self.attack_id_counter += count

    # ===================================================================
    # == NARRATIVE 3: Ransomware (REFACTORED)
    # ===================================================================
    def inject_ransomware_v2(self, count: int):
        """Injects ransomware footprint scenarios N times with refactored event creation."""
        if count == 0: return
        self.logger.info(f"Injecting {count} Ransomware scenarios...")

        # Your original, excellent TTP-based logic is preserved
        cfg = self.config['scenarios']['ransomware']
        families = cfg['ransomware_families']
        family_names = list(families.keys())
        family_weights = [families[name]['weight'] for name in family_names]
        user_activity = Counter(event['actor_email'] for event in self.benign_events if event['actor_email'])
        top_actors = [user for user, count in user_activity.most_common(10)]
        if not top_actors: return

        for i in range(count):
            attack_id = f"ransomware_v2_{self.attack_id_counter + i}"
            chosen_family_name = self.rng.choices(family_names, weights=family_weights, k=1)[0]
            family_data = families[chosen_family_name]
            ransom_extension, ransom_note_name = self._generate_ransomware_indicators(family_data)

            attacker_email = self.rng.choice(top_actors)
            num_files_to_encrypt = self.rng.randint(*cfg['files_to_encrypt'])
            
            victim_events = self.rng.sample(self.benign_events, min(num_files_to_encrypt, len(self.benign_events)))
            base_time = datetime.fromisoformat(self.rng.choice(victim_events)['timestamp'])

            for template_event in victim_events:
                modify_time = base_time + get_random_time_offset(mean_seconds=1800, sigma=1.0, rng=self.rng)
                # Refactored to use create_event_from_template
                modify_event = create_event_from_template(template_event, 
                    {'event_type': 'file_modified', 'actor_email': attacker_email}, 
                    modify_time, attack_id, 2, self.rng)
                self.injected_events.append(modify_event)
                
                rename_time = modify_time + timedelta(seconds=self.rng.randint(1, 10))
                original_name = template_event.get("file_name", "file")
                new_name = original_name + ransom_extension
                rename_event = create_event_from_template(modify_event, 
                    {'event_type': 'file_renamed', 'file_name': new_name, 'details_json': f'{{"old_name": "{original_name}"}}'}, 
                    rename_time, attack_id, 1, self.rng)
                self.injected_events.append(rename_event)

            note_time = base_time + get_random_time_offset(mean_seconds=300, sigma=0.8, rng=self.rng)
            note_template = self.rng.choice(self.benign_events)
            note_event = create_event_from_template(note_template, 
                {'event_type': 'file_created', 'file_name': ransom_note_name, 'actor_email': attacker_email, 'mime_type': 'text/plain'}, 
                note_time, attack_id, 1, self.rng)
            self.injected_events.append(note_event)
        self.attack_id_counter += count

    def _generate_ransomware_indicators(self, family_data: dict) -> tuple[str, str]:
        # This is your excellent original logic, unchanged.
        ext_type = family_data['extension_type']
        if ext_type == "fixed":
            extension = self.rng.choice(family_data['extensions'])
        elif ext_type == "random_alphanumeric":
            length = family_data['extension_length']
            chars = string.ascii_lowercase + string.digits
            extension = f".{''.join(self.rng.choice(chars) for _ in range(length))}"
        elif ext_type == "programmatic_phobos":
            hex_chars = "0123456789abcdef"
            id_part = ''.join(self.rng.choice(hex_chars) for _ in range(8))
            email_part = self.rng.choice(family_data['contact_emails'])
            extension = f".id[{id_part}].[{email_part}].phobos"
        else:
            extension = ".ERROR"
        note_name_template = self.rng.choice(family_data['note_filenames'])
        random_hex = uuid.uuid4().hex[:6]
        note_name = note_name_template.format(extension=extension.lstrip('.'), random=random_hex)
        return extension, note_name

    # ===================================================================
    # == HELPER FUNCTIONS (For the new narrative type)
    # ===================================================================

    def _generate_bulk_events(self, actor_email: str, event_type: str, num_events: int, 
                              base_time: datetime, time_window_minutes: int, 
                              source_events: list, attack_id: str, attack_role: int) -> list:
        # ... (code as provided before)
        injected_events = []
        for _ in range(num_events):
            template_event = self.rng.choice(source_events)
            offset_seconds = self.rng.randint(0, time_window_minutes * 60)
            event_time = base_time + timedelta(seconds=offset_seconds)
            overrides = {'event_type': event_type, 'actor_email': actor_email}
            if event_type == 'file_copied':
                overrides['file_id'] = f"syn_file_{uuid.uuid4()}"
            new_event = create_event_from_template(
                template_event, overrides, event_time, attack_id, attack_role, self.rng)
            injected_events.append(new_event)
        return injected_events

    def _generate_archive_create(self, actor_email: str, base_time: datetime, 
                                 archive_name: str, source_events: list, 
                                 attack_id: str, attack_role: int) -> dict:
        # ... (code as provided before)
        template_event = self.rng.choice(source_events)
        archive_file_id = f"syn_file_{uuid.uuid4()}"
        overrides = {'event_type': 'file_created', 'file_id': archive_file_id, 'file_name': archive_name, 'mime_type': 'application/zip', 'actor_email': actor_email}
        new_event = create_event_from_template(template_event, overrides, base_time, attack_id, attack_role, self.rng)
        return new_event

    def _generate_folder_move(self, actor_email: str, base_time: datetime,
                              target_file_id: str, new_folder_name: str,
                              source_events: list, attack_id: str, attack_role: int) -> dict:
        # ... (code as provided before)
        template_event = self.rng.choice(source_events)
        details = f'{{"source": "unknown", "destination": "{new_folder_name}"}}'
        overrides = {'event_type': 'file_moved', 'file_id': target_file_id, 'actor_email': actor_email, 'details_json': details}
        new_event = create_event_from_template(template_event, overrides, base_time, attack_id, attack_role, self.rng)
        return new_event

    def _generate_external_share(self, actor_email: str, base_time: datetime,
                                 target_file_id: str, share_type: str,
                                 source_events: list, attack_id: str, attack_role: int) -> dict:
        # ... (code as provided before)
        template_event = self.rng.choice(source_events)
        details = '{"new_visibility": "anyoneWithLink"}' if share_type == 'public' else '{"target_user": "attacker.personal.account@gmail.com"}'
        overrides = {'event_type': 'file_shared_externally', 'file_id': target_file_id, 'actor_email': actor_email, 'details_json': details}
        new_event = create_event_from_template(template_event, overrides, base_time, attack_id, attack_role, self.rng)
        return new_event
    
    def inject_project_decommissioning(self, num_trials: int) -> list:
        """
        Injects a benign 'Project Decommissioning' scenario N times.
        This looks like a mass deletion but is labeled as benign (is_malicious=0).

        Args:
            num_trials: The number of mimic scenarios to inject.

        Returns:
            A list of the generated benign mimic events.
        """
        if num_trials == 0: return []
        self.logger.info(f"Injecting {num_trials} trials of 'Project Decommissioning' benign mimic...")
        
        mimic_events = []
        
        user_activity = Counter(event['actor_email'] for event in self.benign_events if event['actor_email'])
        possible_actors = [user for user, count in user_activity.most_common(20)]
        if not possible_actors: return []

        for i in range(num_trials):
            mimic_id = f"benign_mimic_mass_delete_{i}"
            actor_email = self.rng.choice(possible_actors)
            base_time = datetime.fromisoformat(self.rng.choice(self.benign_events)['timestamp'])
            num_files_to_trash = self.rng.randint(50, 200) # Higher volume than some attacks

            # Use the same powerful helper we use for malicious scenarios
            trash_events = self._generate_bulk_events(
                actor_email, 'file_trashed', num_files_to_trash, base_time, 60, 
                self.benign_events, mimic_id, 0 # Role 0: Benign
            )
            
            # CRITICAL STEP: Override the malicious label.
            # create_event_from_template defaults to is_malicious=1. We must fix this.
            for evt in trash_events:
                evt['is_malicious'] = 0
                evt['attack_scenario'] = "benign_mimic_mass_delete" # For traceability
                # Add a reason for explainability
                details = f'{{"benign_reason": "project_decommissioning_simulation"}}'
                evt['details_json'] = details

            mimic_events.extend(trash_events)
            
        return mimic_events