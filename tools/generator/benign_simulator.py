# tools/generator/benign_simulator.py
import logging
import random
import uuid
import string
from datetime import datetime, timedelta, timezone
from collections import Counter

class BenignSimulator:
    """
    Generates a large, realistic, and coherent stream of benign event data by
    simulating daily activities, collaboration, and special contextual scenarios
    aligned with the thesis scope.
    """
    def __init__(self, config: dict, rng: random.Random):
        self.config = config['benign_simulation']
        self.rng = rng
        self.logger = logging.getLogger(self.__class__.__name__)
        self.users = []
        self.virtual_fs = {}
        self.events = []
        self.collaboration_graph = {}
        self.last_special_scenario_day = 0

    def run(self) -> list:
        self.logger.info("Starting benign persona simulation...")
        self._initialize_simulation_state()
        start_date = datetime.now(timezone.utc) - timedelta(days=self.config['simulation_days'])
        for day_index in range(self.config['simulation_days']):
            current_date = start_date + timedelta(days=day_index)
            if day_index % 10 == 0:
                self.logger.info(f"  Simulating day {day_index+1}/{self.config['simulation_days']}...")
            if day_index > 20 and day_index - self.last_special_scenario_day > 15 and self.rng.random() < 0.2:
                self.logger.info(f"  >>> Triggering a special contextual scenario on day {day_index+1}...")
                self._run_special_scenario(current_date)
                self.last_special_scenario_day = day_index
            else:
                for user in self.users:
                    self._simulate_user_activity_for_day(user, current_date)
        self.logger.info(f"Benign simulation complete. Generated {len(self.events)} events.")
        return self.events

    def _initialize_simulation_state(self):
        self.logger.info("Initializing simulation state: creating users and initial files...")
        for persona_name, count in self.config['num_users_per_persona'].items():
            for i in range(count):
                self.users.append({'email': f"{persona_name.replace('_', '.')}.{i+1}@argus-demo.com", 'persona_name': persona_name, 'persona_data': self.config['personas'][persona_name]})
        self.collaboration_graph = {user['email']: Counter() for user in self.users}
        for user in self.users:
            for _ in range(self.rng.randint(5,10)):
                self._handle_file_create(user, datetime.now(timezone.utc) - timedelta(days=self.config['simulation_days']+1))
        self.events = []

    def _simulate_user_activity_for_day(self, user: dict, date: datetime):
        persona = user['persona_data']
        num_actions = max(0, int(self.rng.normalvariate(mu=persona['daily_actions_mean'], sigma=persona['daily_actions_stddev'])))
        for _ in range(num_actions):
            timestamp = self._generate_realistic_timestamp(persona, date)
            if timestamp is None: continue
            ip, device = self._generate_source_metadata(persona)
            actions = [p['event'] for p in persona['action_probabilities']]
            weights = [p['weight'] for p in persona['action_probabilities']]
            action_type = self.rng.choices(actions, weights=weights, k=1)[0]
            # Mapped to actual handlers
            handler_map = {
                'file_created': self._handle_file_create,
                'file_modified': self._handle_file_modify,
                'file_trashed': self._handle_file_trashed,
                'file_shared_internally': self._handle_file_shared_internally,
                'file_shared_externally': self._handle_file_shared_externally,
                'permission_changed': self._handle_permission_changed,
            }
            handler = handler_map.get(action_type)
            if handler:
                handler(user, timestamp, ip, device)

    def _generate_realistic_timestamp(self, persona: dict, date: datetime) -> datetime | None:
        """
        Generates a timestamp that respects work hours, weekly rhythm,
        and handles "overnight" shifts (e.g., [16, 2]).
        """
        is_weekend = date.weekday() >= 5
        if is_weekend and self.rng.random() > persona['weekend_activity_prob']:
            return None

        start_hour, end_hour = persona['work_hours_utc']
        if is_weekend:
            start_hour, end_hour = 0, 23

        # --- THIS IS THE UPGRADED LOGIC ---
        if start_hour > end_hour:
            # Overnight shift (e.g., 16:00 to 02:00 next day)
            # We determine if the action happens in the evening part or the morning part.
            evening_duration = 24 - start_hour
            morning_duration = end_hour
            total_duration = evening_duration + morning_duration
            
            if self.rng.random() < (evening_duration / total_duration):
                # Activity is in the evening (e.g., between 16:00 and 23:59)
                simulated_hour = self.rng.randint(start_hour, 23)
                effective_date = date
            else:
                # Activity is in the early morning (e.g., between 00:00 and 02:00)
                simulated_hour = self.rng.randint(0, end_hour)
                effective_date = date + timedelta(days=1) # The activity happens on the next calendar day
        else:
            # Standard daytime shift
            simulated_hour = self.rng.randint(start_hour, end_hour)
            effective_date = date
        
        return effective_date.replace(
            hour=simulated_hour,
            minute=self.rng.randint(0, 59),
            second=self.rng.randint(0, 59)
        )

    def _generate_source_metadata(self, persona):
        # ... (unchanged)
        ip_category = self.rng.choice(list(persona['ip_addresses'].keys()))
        ip_pool = persona['ip_addresses'][ip_category]
        ip = self.rng.choice(ip_pool)
        devices = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) ...", "Google-Drive-Desktop/67.0.2.0 (Windows)"]
        device = self.rng.choice(devices)
        return ip, device

    def _create_and_log_event(self, event_data):
        # ... (unchanged)
        event_data.update({'is_malicious': 0, 'attack_scenario': None, 'attack_role': 0})
        self.events.append(event_data)

    ### --- Action Handlers --- ###
    # ... (Most are unchanged, sharing handlers are slightly more robust)
    def _handle_file_create(self, user, timestamp, ip="127.0.0.1", device="N/A"):
        file_id = f"sim_file_{uuid.uuid4()}"
        file_name, mime_type = self.rng.choice([("Final_Project.pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"), ("Draft_Essay.docx", "...wordprocessingml.document"), ("Research_Paper.pdf", "application/pdf"), ("client_contract.docx", "..."), ("quarterly_report.xlsx", "...")])
        self.virtual_fs[file_id] = {'name': file_name, 'owner': user['email'], 'trashed': False, 'created_time': timestamp, 'shared_with': set()}
        self._create_and_log_event({'event_id': f"sim_evt_{uuid.uuid4()}", 'timestamp': timestamp.isoformat(), 'actor_email': user['email'], 'ip_address': ip, 'event_type': 'file_created', 'file_id': file_id, 'file_name': file_name, 'mime_type': mime_type, 'details_json': "{}"})
        return file_id

    def _handle_file_modify(self, user, timestamp, ip, device):
        own_files = [fid for fid, meta in self.virtual_fs.items() if meta['owner'] == user['email'] and not meta['trashed']]
        if not own_files: return
        file_id = self.rng.choice(own_files)
        self._create_and_log_event({'event_id': f"sim_evt_{uuid.uuid4()}", 'timestamp': timestamp.isoformat(), 'actor_email': user['email'], 'ip_address': ip, 'event_type': 'file_modified', 'file_id': file_id, 'file_name': self.virtual_fs[file_id]['name'], 'details_json': "{}"})

    def _handle_file_trashed(self, user, timestamp, ip, device):
        own_files = [fid for fid, meta in self.virtual_fs.items() if meta['owner'] == user['email'] and not meta['trashed']]
        if not own_files: return
        file_id = self.rng.choice(own_files)
        self.virtual_fs[file_id]['trashed'] = True
        self._create_and_log_event({'event_id': f"sim_evt_{uuid.uuid4()}", 'timestamp': timestamp.isoformat(), 'actor_email': user['email'], 'ip_address': ip, 'event_type': 'file_trashed', 'file_id': file_id, 'file_name': self.virtual_fs[file_id]['name'], 'details_json': "{}"})
    
    def _handle_file_shared_internally(self, user, timestamp, ip, device, target_file_id=None, target_user_email=None):
        file_id = target_file_id or self.rng.choice([fid for fid, meta in self.virtual_fs.items() if meta['owner'] == user['email'] and not meta['trashed']] or [None])
        if not file_id: return
        if not target_user_email:
            collaborators = self.collaboration_graph[user['email']]
            colleagues = [u for u in self.users if u['email'] != user['email']]
            if not colleagues: return
            target_user_email = self.rng.choices(list(collaborators.keys()), weights=list(collaborators.values()), k=1)[0] if collaborators and self.rng.random() < 0.7 else self.rng.choice(colleagues)['email']
        self.collaboration_graph[user['email']][target_user_email] += 1
        self.virtual_fs[file_id].setdefault('shared_with', set()).add(target_user_email)
        self._create_and_log_event({'event_id': f"sim_evt_{uuid.uuid4()}", 'timestamp': timestamp.isoformat(), 'actor_email': user['email'], 'ip_address': ip, 'event_type': 'file_shared_internally', 'file_id': file_id, 'file_name': self.virtual_fs[file_id]['name'], 'details_json': f'{{"target_user": "{target_user_email}"}}'})

    def _handle_file_shared_externally(self, user, timestamp, ip, device):
        persona = user['persona_data']
        if not persona.get('external_domains') or self.rng.random() > persona.get('external_collaboration_prob', 0.0): return
        own_files = [fid for fid, meta in self.virtual_fs.items() if meta['owner'] == user['email'] and not meta['trashed']]
        if not own_files: return
        file_id_to_share = self.rng.choice(own_files)
        external_domain = self.rng.choice(persona['external_domains'])
        external_email = f"{self.rng.choice(['contact', 'project.lead', 'editor'])}@{external_domain}"
        self.virtual_fs[file_id_to_share].setdefault('shared_with', set()).add(external_email)
        self._create_and_log_event({'event_id': f"sim_evt_{uuid.uuid4()}", 'timestamp': timestamp.isoformat(), 'actor_email': user['email'], 'ip_address': ip, 'event_type': 'file_shared_externally', 'file_id': file_id_to_share, 'file_name': self.virtual_fs[file_id_to_share]['name'], 'details_json': f'{{"target_user": "{external_email}"}}'})

    def _handle_permission_changed(self, user, timestamp, ip, device):
        shared_files = [fid for fid, meta in self.virtual_fs.items() if meta['owner'] == user['email'] and meta.get('shared_with')]
        if not shared_files: return
        file_id_to_change = self.rng.choice(shared_files)
        target_user = self.rng.choice(list(self.virtual_fs[file_id_to_change]['shared_with']))
        new_permission = self.rng.choice(['editor', 'commenter'])
        self._create_and_log_event({'event_id': f"sim_evt_{uuid.uuid4()}", 'timestamp': timestamp.isoformat(), 'actor_email': user['email'], 'ip_address': ip, 'event_type': 'permission_changed', 'file_id': file_id_to_change, 'file_name': self.virtual_fs[file_id_to_change]['name'], 'details_json': f'{{"target_user": "{target_user}", "new_permission": "{new_permission}"}}'})

    ### --- Special Contextual Scenarios --- ###
    def _run_special_scenario(self, date: datetime):
        # ... (unchanged)
        scenario_choice = self.rng.choice(['quarterly_report', 'new_hire_onboarding'])
        if scenario_choice == 'quarterly_report': self._run_quarterly_report_scenario(date)
        elif scenario_choice == 'new_hire_onboarding': self._run_new_hire_onboarding_scenario(date)

    def _run_quarterly_report_scenario(self, start_date: datetime):
        # ... (unchanged)
        self.logger.info("    >>> Running Special Scenario: Quarterly Report Release")
        creator = self.rng.choice([u for u in self.users if u['persona_name'] == 'sales_executive'])
        timestamp = self._generate_realistic_timestamp(creator['persona_data'], start_date)
        if timestamp is None: self.logger.warning("      Could not generate valid timestamp for report creator. Skipping scenario."); return
        ip, device = self._generate_source_metadata(creator['persona_data'])
        report_file_id = self._handle_file_create(creator, timestamp, ip, device)
        downloaders = [u for u in self.users if u['persona_name'] in ['sales_executive', 'marketing_specialist']]
        for user in downloaders:
            for _ in range(self.rng.randint(1, 3)):
                dl_date = start_date + timedelta(days=self.rng.uniform(0, 2))
                dl_timestamp = self._generate_realistic_timestamp(user['persona_data'], dl_date)
                if dl_timestamp is None: continue
                dl_ip, dl_device = self._generate_source_metadata(user['persona_data'])
                self._create_and_log_event({'event_id': f"sim_evt_{uuid.uuid4()}", 'timestamp': dl_timestamp.isoformat(), 'actor_email': user['email'], 'ip_address': dl_ip, 'event_type': 'file_downloaded', 'file_id': report_file_id, 'file_name': self.virtual_fs[report_file_id]['name']})

    def _run_new_hire_onboarding_scenario(self, start_date: datetime):
        # ... (unchanged)
        self.logger.info("    >>> Running Special Scenario: New Hire Onboarding")
        try:
            hr_user = self.rng.choice([u for u in self.users if u['persona_name'] == 'hr_manager'])
            new_hire = self.rng.choice([u for u in self.users if u['persona_name'] == 'software_engineer'])
        except IndexError: self.logger.warning("      Could not find required personas for onboarding. Skipping."); return
        project_files = [fid for fid, meta in self.virtual_fs.items() if meta['owner'] != hr_user['email']]
        if len(project_files) < 20: return
        files_to_share = self.rng.sample(project_files, self.rng.randint(15, 20))
        for file_id in files_to_share:
            share_date = start_date + timedelta(minutes=self.rng.uniform(0, 60))
            share_timestamp = self._generate_realistic_timestamp(hr_user['persona_data'], share_date)
            if share_timestamp is None: continue
            ip, device = self._generate_source_metadata(hr_user['persona_data'])
            self._handle_file_shared_internally(hr_user, share_timestamp, ip, device, target_file_id=file_id, target_user_email=new_hire['email'])