-- app/db/schema.sql (Complete and Corrected for SQLite)

-- Ensures that foreign key constraints are enforced.
PRAGMA foreign_keys=ON;

-- Stores application metadata, like API page tokens.
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Stores metadata for every file cataloged by Argus.
CREATE TABLE IF NOT EXISTS files (
  id TEXT PRIMARY KEY,
  name TEXT,
  mime_type TEXT,
  created_time TEXT,
  modified_time TEXT,
  trashed INTEGER DEFAULT 0,
  parents_json TEXT,
  md5Checksum TEXT,
  vt_scan_ts TEXT,
  vt_positives INTEGER,
  is_shared_externally INTEGER DEFAULT 0,
  is_shared_publicly INTEGER DEFAULT 0
);

-- Index to speed up copy detection during initial scans.
CREATE INDEX IF NOT EXISTS idx_files_md5Checksum ON files(md5Checksum);

-- Stores known Google Drive user accounts.
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    display_name TEXT,
    email TEXT
);

-- Stores every individual event detected in Google Drive.
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    drive_change_id TEXT UNIQUE NOT NULL,
    file_id TEXT,
    event_type TEXT NOT NULL,
    actor_user_id TEXT,
    ts TEXT NOT NULL,
    details_json TEXT,
    is_analyzed INTEGER DEFAULT 0 NOT NULL, -- ADDED: Tracks if the event has been scored.
    FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE SET NULL,
    FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Stores detected multi-event threat narratives.
CREATE TABLE IF NOT EXISTS narratives (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    start_ts TEXT NOT NULL,
    end_ts TEXT NOT NULL,
    threat_score REAL NOT NULL,
    summary TEXT
);

-- A linking table between narratives and the events that comprise them.
CREATE TABLE IF NOT EXISTS narrative_events (
    narrative_id INTEGER NOT NULL,
    event_id INTEGER NOT NULL,
    PRIMARY KEY (narrative_id, event_id),
    FOREIGN KEY (narrative_id) REFERENCES narratives(id) ON DELETE CASCADE,
    FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
);

-- Stores the calculated behavioral baseline for each user.
CREATE TABLE IF NOT EXISTS user_baseline (
    user_id TEXT PRIMARY KEY,
    typical_activity_hours_json TEXT,
    avg_daily_deletions REAL DEFAULT 0,
    max_historical_deletions INTEGER DEFAULT 0,
    has_performed_mass_cleanup INTEGER DEFAULT 0,
    last_updated_ts TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);