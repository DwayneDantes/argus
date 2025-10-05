# tools/generator/scenarios.py
import logging
import random
import uuid
import string
from datetime import datetime, timedelta
from collections import Counter
from .utils import create_event_from_template, get_random_time_offset

class ScenarioInjector:
    """
    Contains the logic for injecting all defined malicious scenarios.
    """
    def __init__(self, config, benign_events, rng: random.Random):
        self.config = config
        self.benign_events = benign_events
        self.rng = rng
        self.logger = logging.getLogger(self.__class__.__name__)
        self.injected_events = []
        self.attack_id_counter = 0

    def run_injections(self, start_attack_id=1):
        """Runs all enabled scenario injectors."""
        self.attack_id_counter = start_attack_id
        self.logger.info("Starting injection of malicious scenarios...")

        if not self.benign_events:
            self.logger.warning("Benign event canvas is empty. Skipping all injections.")
            return [], self.attack_id_counter

        if self.config['scenarios']['data_exfiltration']['enabled']:
            self._inject_data_exfiltration()
        if self.config['scenarios']['mass_deletion']['enabled']:
            self._inject_mass_deletion()
        if self.config['scenarios']['ransomware']['enabled']:
            self._inject_ransomware()

        return self.injected_events, self.attack_id_counter

    def _get_next_attack_id(self, prefix: str) -> str:
        attack_id = f"{prefix}_{self.attack_id_counter:03d}"
        self.attack_id_counter += 1
        return attack_id

    def _inject_data_exfiltration(self):
        """
        Injects exfiltration patterns with varying "low-and-slow" vs "smash_and_grab"
        profiles, based on the V4 configuration.
        """
        cfg = self.config['scenarios']['data_exfiltration']
        count = cfg['count']
        profiles = cfg['profiles']
        profile_names = [p['name'] for p in profiles]
        profile_weights = [p['weight'] for p in profiles]

        self.logger.info(f"Injecting {count} Data Exfiltration scenarios...")

        for _ in range(count):
            # --- NEW: Select an attack profile based on configured weights ---
            chosen_profile_name = self.rng.choices(profile_names, weights=profile_weights, k=1)[0]
            profile_data = next(p for p in profiles if p['name'] == chosen_profile_name)
            
            attack_id = self._get_next_attack_id(f"exfil_{chosen_profile_name}")
            self.logger.debug(f"  Generating exfil chain ({chosen_profile_name}): {attack_id}")

            template_event = self.rng.choice(self.benign_events)
            base_time = datetime.fromisoformat(template_event['timestamp'])

            if self.rng.choice([True, False]):
                # --- FLAVOR A: High-Confidence (Copy -> Rename -> Share) ---
                copy_time = base_time + get_random_time_offset(60, 300, self.rng)
                new_file_id = f"syn_file_{uuid.uuid4()}"
                copy_event = create_event_from_template(template_event, {'event_type': 'file_copied', 'file_id': new_file_id, 'details_json': f'{{"source_file_id": "{template_event["file_id"]}"}}'}, copy_time, attack_id, 2, self.rng)
                self.injected_events.append(copy_event)
                
                # Use delays from the dynamically chosen profile
                rename_time = copy_time + get_random_time_offset(*profile_data['rename_delay_seconds'], self.rng)
                obfuscated_name = f".{template_event.get('file_name', 'untitled')}"
                rename_event = create_event_from_template(copy_event, {'event_type': 'file_renamed', 'file_name': obfuscated_name, 'details_json': f'{{"old_name": "{template_event.get("file_name", "untitled")}"}}'}, rename_time, attack_id, 2, self.rng)
                self.injected_events.append(rename_event)

                share_time = rename_time + get_random_time_offset(*profile_data['share_delay_seconds'], self.rng)
                share_event = create_event_from_template(rename_event, {'event_type': 'file_shared_externally', 'details_json': '{"new_visibility": "anyoneWithLink"}'}, share_time, attack_id, 1, self.rng)
                self.injected_events.append(share_event)
            else:
                # --- FLAVOR B: Medium-Confidence (Rename -> Share) ---
                rename_time = base_time + get_random_time_offset(*profile_data['rename_delay_seconds'], self.rng)
                obfuscated_name = f".{template_event.get('file_name', 'untitled')}"
                rename_event = create_event_from_template(template_event, {'event_type': 'file_renamed', 'file_name': obfuscated_name, 'details_json': f'{{"old_name": "{template_event.get("file_name", "untitled")}"}}'}, rename_time, attack_id, 2, self.rng)
                self.injected_events.append(rename_event)
                
                share_time = rename_time + get_random_time_offset(*profile_data['share_delay_seconds'], self.rng)
                share_event = create_event_from_template(rename_event, {'event_type': 'file_shared_externally', 'details_json': '{"new_visibility": "anyoneWithLink"}'}, share_time, attack_id, 1, self.rng)
                self.injected_events.append(share_event)

    def _inject_mass_deletion(self):
        # (Code from previous milestone - unchanged)
        cfg = self.config['scenarios']['mass_deletion']
        count = cfg['count']
        self.logger.info(f"Injecting {count} Mass Deletion scenarios...")
        user_activity = Counter(event['actor_email'] for event in self.benign_events if event['actor_email'])
        top_actors = [user for user, count in user_activity.most_common(10)]
        if not top_actors: return
        victim_file_pool = {event['file_id']: event for event in self.benign_events if event['file_id']}
        if not victim_file_pool: return
        for _ in range(count):
            attack_id = self._get_next_attack_id("massdel")
            self.logger.debug(f"  Generating mass deletion chain: {attack_id}")
            attacker_email = self.rng.choice(top_actors)
            num_files_to_trash = min(self.rng.randint(*cfg['files_to_trash']), len(victim_file_pool))
            if num_files_to_trash == 0: continue
            victim_file_ids = self.rng.sample(list(victim_file_pool.keys()), num_files_to_trash)
            base_time = datetime.fromisoformat(self.rng.choice(self.benign_events)['timestamp'])
            window_minutes = self.rng.randint(*cfg['time_window_minutes'])
            trashed_file_records = []
            for file_id in victim_file_ids:
                template_event = victim_file_pool[file_id]
                trash_time = base_time + timedelta(seconds=self.rng.randint(0, window_minutes * 60))
                trash_event = create_event_from_template(template_event, {'event_type': 'file_trashed', 'actor_email': attacker_email}, trash_time, attack_id, 2, self.rng)
                self.injected_events.append(trash_event)
                trashed_file_records.append({'event': trash_event, 'time': trash_time})
            perm_delete_ratio = self.rng.uniform(*cfg['perm_delete_ratio'])
            num_to_perm_delete = int(len(trashed_file_records) * perm_delete_ratio)
            files_to_perm_delete = self.rng.sample(trashed_file_records, num_to_perm_delete)
            for record in files_to_perm_delete:
                perm_delete_time = record['time'] + get_random_time_offset(60, 600, self.rng)
                perm_delete_event = create_event_from_template(record['event'], {'event_type': 'file_deleted_permanently'}, perm_delete_time, attack_id, 1, self.rng)
                self.injected_events.append(perm_delete_event)

    def _generate_ransomware_indicators(self, family_data: dict) -> tuple[str, str]:
        """Generates a specific file extension and note name based on the family's TTPs."""
        ext_type = family_data['extension_type']
        extension = ".ERROR"

        if ext_type == "fixed":
            extension = self.rng.choice(family_data['extensions'])
        elif ext_type == "random_alphanumeric":
            length = family_data['extension_length']
            chars = string.ascii_lowercase + string.digits
            random_part = ''.join(self.rng.choice(chars) for _ in range(length))
            extension = f".{random_part}"
        elif ext_type == "programmatic_phobos":
            hex_chars = "0123456789abcdef"
            id_part = ''.join(self.rng.choice(hex_chars) for _ in range(8))
            email_part = self.rng.choice(family_data['contact_emails'])
            extension = f".id[{id_part}].[{email_part}].phobos"
            
        note_name_template = self.rng.choice(family_data['note_filenames'])
        extension_for_template = extension.lstrip('.')
        # Use a random hex string for placeholders like in REvil notes
        random_hex = uuid.uuid4().hex[:6]
        note_name = note_name_template.format(extension=extension_for_template, random=random_hex)
        return extension, note_name

    def _inject_ransomware(self):
        """
        Injects a ransomware footprint based on a weighted, random selection
        of real-world ransomware family TTPs.
        """
        cfg = self.config['scenarios']['ransomware']
        count = cfg['count']
        self.logger.info(f"Injecting {count} Ransomware scenarios...")

        # --- Pre-computation for realism ---
        families = cfg['ransomware_families']
        family_names = list(families.keys())
        family_weights = [families[name]['weight'] for name in family_names]
        user_activity = Counter(event['actor_email'] for event in self.benign_events if event['actor_email'])
        top_actors = [user for user, count in user_activity.most_common(10)]
        if not top_actors: return
        victim_file_pool = {event['file_id']: event for event in self.benign_events if event['file_id']}
        if not victim_file_pool: return

        for _ in range(count):
            attack_id = self._get_next_attack_id("ransom")
            
            # --- 1. Select a Ransomware Family (Weighted) ---
            chosen_family_name = self.rng.choices(family_names, weights=family_weights, k=1)[0]
            family_data = families[chosen_family_name]
            self.logger.debug(f"  Generating ransomware chain ({chosen_family_name}): {attack_id}")

            # --- 2. Generate Indicators for this specific attack ---
            ransom_extension, ransom_note_name = self._generate_ransomware_indicators(family_data)

            # --- 3. Victim and Attacker Selection ---
            attacker_email = self.rng.choice(top_actors)
            num_files_to_encrypt = min(self.rng.randint(*cfg['files_to_encrypt']), len(victim_file_pool))
            if num_files_to_encrypt == 0: continue
            victim_file_ids = self.rng.sample(list(victim_file_pool.keys()), num_files_to_encrypt)
            base_time = datetime.fromisoformat(self.rng.choice(self.benign_events)['timestamp'])
            
            # --- 4. Stage 1: The "Encryption" (Modify -> Rename) ---
            for file_id in victim_file_ids:
                template_event = victim_file_pool[file_id]
                
                modify_time = base_time + get_random_time_offset(1, 3600, self.rng) # Within a 1-hour window
                modify_event = create_event_from_template(template_event, {'event_type': 'file_modified', 'actor_email': attacker_email}, modify_time, attack_id, 2, self.rng)
                self.injected_events.append(modify_event)
                
                rename_time = modify_time + get_random_time_offset(1, 10, self.rng) # Rename is fast
                original_name = template_event.get("file_name", "file")
                new_name = original_name + ransom_extension
                rename_event = create_event_from_template(modify_event, {'event_type': 'file_renamed', 'file_name': new_name, 'details_json': f'{{"old_name": "{original_name}"}}'}, rename_time, attack_id, 1, self.rng)
                self.injected_events.append(rename_event)

            # --- 5. Stage 2: Dropping the Ransom Note ---
            note_time = base_time + get_random_time_offset(60, 3000, self.rng)
            note_template = self.rng.choice(list(victim_file_pool.values())) # Use a random file for context
            note_event = create_event_from_template(note_template, {'event_type': 'file_created', 'file_name': ransom_note_name, 'actor_email': attacker_email, 'mime_type': 'text/plain'}, note_time, attack_id, 1, self.rng)
            self.injected_events.append(note_event)