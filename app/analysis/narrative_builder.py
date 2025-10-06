# app/analysis/narrative_builder.py (UPGRADED for Milestone 3.2)

import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

# --- 1. Narrative Templates ---
# In a real system, this would be loaded from a JSON/YAML file.
NARRATIVE_TEMPLATES = {
    "stage_archive_exfil_v1": {
        "id": "stage_archive_exfil_v1",
        "description": "Actor performs a high volume of copies, creates an archive, then shares it externally.",
        "starter_patterns": ["bulk_copy"], # Which micro-patterns can start this narrative
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

# --- 2. State Management for Active FSMs ---
# Maps: actor_id -> list of active FSM instances for that actor
ACTIVE_FSMS = defaultdict(list)

# --- 3. The FSM Class ---
class NarrativeFSM:
    """An instance of a potential narrative being tracked for a single actor."""
    def __init__(self, template: dict, actor_id: str):
        self.template = template
        self.actor_id = actor_id
        self.state = 0  # Current step in the narrative we are looking for
        self.start_time = datetime.now(timezone.utc)
        self.last_advance_time = self.start_time
        self.evidence = {} # Maps step type to the micro-pattern data

    def advance(self, micro_pattern_type: str, micro_pattern_data: dict):
        """Attempts to advance the FSM's state with a new micro-pattern."""
        if self.state >= len(self.template['ordered_steps']):
            return "ALREADY_COMPLETE" # Should not happen if managed correctly

        expected_step = self.template['ordered_steps'][self.state]
        
        if micro_pattern_type == expected_step['type']:
            self.state += 1
            self.evidence[micro_pattern_type] = micro_pattern_data
            self.last_advance_time = datetime.now(timezone.utc)
            
            if self.state == len(self.template['ordered_steps']):
                return "COMPLETE"
            return "ADVANCED"
        return "NO_MATCH"

    def is_expired(self) -> bool:
        """Checks if the FSM has exceeded its total allowed lifetime."""
        return (datetime.now(timezone.utc) - self.start_time).total_seconds() > (self.template['total_time_window_minutes'] * 60)

# --- 4. The Main Analysis Function ---
def analyze_narratives_for_actor(actor_id: str, micro_patterns: dict) -> dict | None:
    """
    Manages the lifecycle of FSMs for a given actor and checks for completed narratives.
    """
    completed_narrative = None

    # --- Step A: Prune expired FSMs ---
    ACTIVE_FSMS[actor_id] = [fsm for fsm in ACTIVE_FSMS[actor_id] if not fsm.is_expired()]

    # --- Step B: Advance all active FSMs with newly detected patterns ---
    for fsm in ACTIVE_FSMS[actor_id]:
        for pattern_type, pattern_data in micro_patterns.items():
            result = fsm.advance(pattern_type, pattern_data)
            if result == "COMPLETE":
                logger.info(f"NARRATIVE DETECTED for actor {actor_id}: {fsm.template['id']}")
                completed_narrative = {
                    "narrative_type": fsm.template['id'],
                    "score": fsm.template['base_score'],
                    "reason": fsm.template['reason'],
                    "evidence": fsm.evidence,
                    "primary_actor_id": fsm.actor_id,
                    "start_time": fsm.start_time.isoformat(),
                    "end_time": datetime.now(timezone.utc).isoformat()
                }
                break
        if completed_narrative:
            break

    # --- Step C: Instantiate NEW FSMs if a "starter" pattern is seen ---
    # This must be done AFTER advancing, to avoid advancing a new FSM with the same pattern that started it.
    for pattern_type, pattern_data in micro_patterns.items():
        for template_name, template in NARRATIVE_TEMPLATES.items():
            if pattern_type in template.get("starter_patterns", []):
                is_already_running = any(fsm.template['id'] == template_name for fsm in ACTIVE_FSMS[actor_id])
                if not is_already_running:
                    logger.info(f"Instantiating new FSM '{template_name}' for actor {actor_id}")
                    new_fsm = NarrativeFSM(template, actor_id)
                    new_fsm.advance(pattern_type, pattern_data) # Advance with the starter pattern
                    ACTIVE_FSMS[actor_id].append(new_fsm)

    # Clean up completed FSMs after they have fired
    if completed_narrative:
        ACTIVE_FSMS[actor_id] = [fsm for fsm in ACTIVE_FSMS[actor_id] if fsm.state < len(fsm.template['ordered_steps'])]

    return completed_narrative