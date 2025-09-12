PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS files (
  id TEXT PRIMARY KEY,
  name TEXT,
  mime_type TEXT,
  created_time TEXT,
  modified_time TEXT,
  trashed INTEGER DEFAULT 0,
  parents_json TEXT,
  md5Checksum TEXT -- ADDED: To store the file's content fingerprint.
);

-- ADDED: An index for super-fast searching of file content hashes.
CREATE INDEX IF NOT EXISTS idx_files_md5Checksum ON files(md5Checksum);

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  display_name TEXT,
  email TEXT
);

CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  drive_change_id TEXT UNIQUE NOT NULL,
  file_id TEXT,
  event_type TEXT NOT NULL,
  actor_user_id TEXT,
  ts TEXT NOT NULL,
  details_json TEXT,
  FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE SET NULL,
  FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS narratives (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  start_ts TEXT NOT NULL,
  end_ts TEXT NOT NULL,
  threat_score REAL NOT NULL,
  summary TEXT
);

CREATE TABLE IF NOT EXISTS narrative_events (
  narrative_id INTEGER NOT NULL,
  event_id INTEGER NOT NULL,
  PRIMARY KEY (narrative_id, event_id),
  FOREIGN KEY (narrative_id) REFERENCES narratives(id) ON DELETE CASCADE,
  FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
);