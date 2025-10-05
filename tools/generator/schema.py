# tools/generator/schema.py

# This list defines the canonical schema for our final, flat ML dataset table.
# The generator's primary job is to produce a table with exactly these columns.
CANONICAL_EVENT_COLUMNS = [
    # Core Event Identifiers
    "event_id",          # Unique ID for the event (str, from drive_change_id or new UUID)
    "timestamp",         # ISO 8601 UTC timestamp (str, from events.ts)

    # Actor & Source Information
    "actor_email",       # User email (str, requires JOIN on users table)
    "ip_address",        # Source IP of the event (str, nullable, from details_json)

    # Event & File Information
    "event_type",        # e.g., 'file_renamed', 'file_shared_externally' (str)
    "file_id",           # Google Drive file ID (str)
    "file_name",         # File name at the time of the event (str, requires JOIN on files table)
    "mime_type",         # File mime type (str, requires JOIN on files table)
    "size_bytes",        # File size in bytes (int, nullable, from details_json or files table)

    # Rich Details for Featurization
    "details_json",      # Raw JSON details for rich feature extraction (str)

    # --- GROUND TRUTH LABELS (Our Contribution) ---
    "is_malicious",      # Our primary label (int, 0 or 1)
    "attack_scenario",   # Unique ID for the attack instance, e.g., 'exfil_1' (str, nullable)
    "attack_role"        # Granular role within the attack narrative (int, nullable)
]

# Definition for the granular attack_role label
ATTACK_ROLE_MAP = {
    0: "Benign",
    1: "Causal/Core Malicious",       # The key event achieving the objective (e.g., external share)
    2: "Ancillary/Preparatory Malicious", # An event enabling the core event (e.g., rename for obfuscation)
    3: "Deceptive/Noise Malicious"    # A benign-looking event injected as cover by the attacker
}