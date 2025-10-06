# app/analysis/narrative_builder.py (IMPROVED - Tracks Event IDs)

import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

NARRATIVE_TEMPLATES = {
    "stage_archive_exfil_v1": {
        "id": "stage_archive_exfil_v1",
        "description": "Actor performs a high volume of copies, creates an archive, then shares it externally.",
        "starter_patterns": ["bulk_copy"],
        "ordered_steps": [
            {'type': 'bulk_copy'},
            {'type': 'archive_create'},
            {'type': 'external_share'}
        ],
        "total_time_window_minutes": 120,
        "base_score": 75.0,
        "reason": "NR: Detected a staged data exfiltration pattern (Bulk Copy -> Archive -> Share)."
    }
}

ACTIVE_FSMS = defaultdict(list)

class NarrativeFSM:
    """An instance of a potential narrative being tracked for a single actor."""
    def __init__(self, template: dict, actor_id: str):
        self.template = template
        self.actor_id = actor_id
        self.state = 0
        self.start_time = datetime.now(timezone.utc)
        self.last_advance_time = self.start_time
        self.evidence = {}
        self.event_ids = []

    def advance(self, micro_pattern_type: str, micro_pattern_data: dict, event_id: int = None):
        """
        Attempts to advance the FSM's state with a new micro-pattern.
        Now also tracks the event ID that triggered this step.
        """
        if self.state >= len(self.template['ordered_steps']):
            return "ALREADY_COMPLETE"

        expected_step = self.template['ordered_steps'][self.state]
        
        if micro_pattern_type == expected_step['type']:
            self.state += 1
            self.evidence[micro_pattern_type] = micro_pattern_data
            
            if event_id:
                self.event_ids.append({
                    'event_id': event_id,
                    'stage': micro_pattern_type
                })
            
            self.last_advance_time = datetime.now(timezone.utc)
            
            if self.state == len(self.template['ordered_steps']):
                return "COMPLETE"
            return "ADVANCED"
        return "NO_MATCH"

    def is_expired(self) -> bool:
        """Checks if the FSM has exceeded its total allowed lifetime."""
        elapsed_seconds = (datetime.now(timezone.utc) - self.start_time).total_seconds()
        max_seconds = self.template['total_time_window_minutes'] * 60
        return elapsed_seconds > max_seconds

def analyze_narratives_for_actor(actor_id: str, micro_patterns: dict, current_event_id: int = None) -> dict | None:
    """
    Manages the lifecycle of FSMs for a given actor and checks for completed narratives.
    NOW ACCEPTS: current_event_id to track which events are part of narratives.
    """
    completed_narrative = None
    
    if micro_patterns:
        pattern_types = list(micro_patterns.keys())
        logger.info(f"[ANALYZE] Actor {actor_id} with patterns: {pattern_types}")

    before_prune = len(ACTIVE_FSMS[actor_id])
    ACTIVE_FSMS[actor_id] = [fsm for fsm in ACTIVE_FSMS[actor_id] if not fsm.is_expired()]
    after_prune = len(ACTIVE_FSMS[actor_id])
    if before_prune > after_prune:
        logger.info(f"🧹 Pruned {before_prune - after_prune} expired FSMs for actor {actor_id}")

    for fsm in ACTIVE_FSMS[actor_id]:
        total_steps = len(fsm.template['ordered_steps'])
        logger.debug(f"  FSM '{fsm.template['id']}' at step {fsm.state}/{total_steps}")
        for pattern_type, pattern_data in micro_patterns.items():
            result = fsm.advance(pattern_type, pattern_data, current_event_id)
            if result == "ADVANCED":
                logger.info(f"  ⏩ FSM '{fsm.template['id']}' advanced to step {fsm.state}")
            if result == "COMPLETE":
                logger.info(f"🎯 NARRATIVE DETECTED for actor {actor_id}: {fsm.template['id']}")
                completed_narrative = {
                    "narrative_type": fsm.template['id'],
                    "score": fsm.template['base_score'],
                    "reason": fsm.template['reason'],
                    "evidence": fsm.evidence,
                    "primary_actor_id": fsm.actor_id,
                    "start_time": fsm.start_time.isoformat(),
                    "end_time": datetime.now(timezone.utc).isoformat(),
                    "event_ids": fsm.event_ids
                }
                break
        if completed_narrative:
            break

    for pattern_type, pattern_data in micro_patterns.items():
        for template_name, template in NARRATIVE_TEMPLATES.items():
            if pattern_type in template.get("starter_patterns", []):
                is_already_running = any(
                    fsm.template['id'] == template_name 
                    for fsm in ACTIVE_FSMS[actor_id]
                )
                if not is_already_running:
                    logger.info(f"📍 Starting new narrative tracker '{template_name}' for actor {actor_id}")
                    new_fsm = NarrativeFSM(template, actor_id)
                    new_fsm.advance(pattern_type, pattern_data, current_event_id)
                    ACTIVE_FSMS[actor_id].append(new_fsm)

    if completed_narrative:
        ACTIVE_FSMS[actor_id] = [
            fsm for fsm in ACTIVE_FSMS[actor_id] 
            if fsm.state < len(fsm.template['ordered_steps'])
        ]

    return completed_narrative