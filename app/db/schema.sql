-- schema.sql (FINAL, CORRECTED, AND COMPLETE VERSION)

PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  display_name TEXT,
  email TEXT
);

CREATE TABLE IF NOT EXISTS files (
  id TEXT PRIMARY KEY,
  name TEXT,
  mime_type TEXT,
  created_time TEXT,
  modified_time TEXT,
  trashed INTEGER DEFAULT 0,
  parents_json TEXT,
  md5Checksum TEXT,
  is_shared_externally INTEGER DEFAULT 0,
  is_shared_publicly INTEGER DEFAULT 0,
  vt_scan_ts TEXT,
  vt_positives INTEGER
);

CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  drive_change_id TEXT UNIQUE,
  file_id TEXT,
  event_type TEXT,
  actor_user_id TEXT,
  ts TIMESTAMP,
  details_json TEXT,
  is_analyzed INTEGER DEFAULT 0,
  FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE SET NULL,
  FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS user_baseline (
    user_id TEXT PRIMARY KEY,
    typical_activity_hours_json TEXT,
    avg_daily_deletions REAL,
    max_historical_deletions INTEGER,
    has_performed_mass_cleanup INTEGER,
    last_updated_ts TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- The NEW, CORRECT tables for narrative persistence
CREATE TABLE IF NOT EXISTS narratives (
    narrative_id INTEGER PRIMARY KEY AUTOINCREMENT,
    narrative_type TEXT NOT NULL,
    primary_actor_id TEXT NOT NULL,
    start_time TIMESTAMP NOT NULL,
    end_time TIMESTAMP NOT NULL,
    final_score REAL NOT NULL,
    status TEXT DEFAULT 'new' NOT NULL
);

CREATE TABLE IF NOT EXISTS narrative_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    narrative_id INTEGER NOT NULL,
    event_id INTEGER NOT NULL,
    stage TEXT,
    FOREIGN KEY (narrative_id) REFERENCES narratives (narrative_id) ON DELETE CASCADE,
    FOREIGN KEY (event_id) REFERENCES events (id) ON DELETE CASCADE
);