# tools/generator/utils.py
import uuid
from datetime import datetime, timedelta, timezone
import random

def create_event_from_template(
    template_event: dict,
    overrides: dict,
    timestamp: datetime,
    attack_id: str,
    attack_role: int,
    rng: random.Random
) -> dict:
    """
    Creates a new synthetic event dictionary based on a template.

    This function handles the generation of a new unique event ID, sets the
    timestamp, applies all specific overrides, and attaches the required
    maliciousness labels.

    Args:
        template_event: A dictionary of a real benign event to use as a base.
        overrides: A dictionary of key-value pairs to set or change on the template.
        timestamp: The precise datetime object for the new event.
        attack_id: The unique scenario ID for this attack chain (e.g., 'exfil_001').
        attack_role: The granular role of this specific event in the attack.
        rng: The random number generator instance for any random elements.

    Returns:
        A new event dictionary in the canonical format.
    """
    new_event = template_event.copy()

    # Apply all specified overrides
    new_event.update(overrides)

    # Set core metadata for the new event
    new_event['event_id'] = f"syn_{uuid.uuid4()}"
    new_event['timestamp'] = timestamp.isoformat()

    # --- Set ground-truth labels ---
    new_event['is_malicious'] = 1
    new_event['attack_scenario'] = attack_id
    new_event['attack_role'] = attack_role

    # Forge a basic details_json if not provided in overrides.
    # This ensures the column is always present.
    if 'details_json' not in new_event or not new_event['details_json']:
        new_event['details_json'] = "{}"

    return new_event

def get_random_time_offset(min_seconds: int, max_seconds: int, rng: random.Random) -> timedelta:
    """Returns a timedelta with a random number of seconds between min and max."""
    return timedelta(seconds=rng.randint(min_seconds, max_seconds))