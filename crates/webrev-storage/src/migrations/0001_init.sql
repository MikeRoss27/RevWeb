-- crates/webrev-storage/src/migrations/0001_init.sql
-- Initial schema. Idempotent so it can run on every startup.

CREATE TABLE IF NOT EXISTS sessions (
    id         TEXT PRIMARY KEY NOT NULL,
    name       TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS findings (
    id         TEXT PRIMARY KEY NOT NULL,
    session_id TEXT NOT NULL,
    kind       TEXT NOT NULL,
    url        TEXT,
    value      TEXT NOT NULL,
    confidence TEXT NOT NULL,
    source     TEXT NOT NULL,
    location   TEXT
);

CREATE TABLE IF NOT EXISTS endpoints (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    url        TEXT NOT NULL,
    method     TEXT NOT NULL,
    source     TEXT NOT NULL,
    scope      TEXT NOT NULL DEFAULT 'internal'
);

-- Secrets are stored ONLY as non-reversible fingerprints (see
-- webrev-core::security::sanitize). Plaintext never touches the database.
CREATE TABLE IF NOT EXISTS secrets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT NOT NULL,
    fingerprint TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_session ON findings (session_id);
CREATE INDEX IF NOT EXISTS idx_endpoints_session ON endpoints (session_id);
