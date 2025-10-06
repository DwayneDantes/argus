# tools/generator/utils.py
import uuid
from datetime import datetime, timedelta, timezone
import random
import math

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


    # Set ground-truth labels, allowing overrides
    new_event['is_malicious'] = overrides.get('is_malicious', 1) # Default to 1 if not specified
    new_event['attack_scenario'] = attack_id
    new_event['attack_role'] = attack_role

    # Forge a basic details_json if not provided in overrides.
    # This ensures the column is always present.
    if 'details_json' not in new_event or not new_event['details_json']:
        new_event['details_json'] = "{}"

    return new_event

def get_random_time_offset(mean_seconds: int, sigma: float, rng: random.Random) -> timedelta:
    """
    Returns a timedelta sampled from a Log-Normal distribution.
    This models behavior where most delays are short, but some are very long.
    
    Args:
        mean_seconds: The desired median delay in seconds.
        sigma: Controls the spread/variance. A good starting value is 0.5 to 1.0.
        rng: The random number generator instance.

    Returns:
        A timedelta object.
    """
    # lognormvariate takes mu (the mean of the underlying log) and sigma.
    # We convert our desired median (mean_seconds) to the required mu parameter.
    mu = math.log(mean_seconds)
    
    delay_seconds = rng.lognormvariate(mu, sigma)
    
    # Ensure the delay is at least 1 second to avoid zero-delay events
    return timedelta(seconds=max(1, int(delay_seconds)))