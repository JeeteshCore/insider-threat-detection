-- db/schema.sql

CREATE TABLE IF NOT EXISTS auth_users (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    username         TEXT    NOT NULL UNIQUE,
    email            TEXT    NOT NULL UNIQUE,
    password_hash    TEXT    NOT NULL,
    role             TEXT    DEFAULT 'analyst',
    created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login       TIMESTAMP,
    failed_attempts  INTEGER DEFAULT 0,
    locked_until     TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT    NOT NULL UNIQUE,
    role        TEXT    DEFAULT 'employee',
    department  TEXT    DEFAULT 'general',
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS login_events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    username     TEXT    NOT NULL,
    login_time   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address   TEXT,
    device       TEXT,
    status       TEXT    DEFAULT 'success',
    login_hour   INTEGER,
    is_off_hours INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS file_access_events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    username     TEXT    NOT NULL,
    file_path    TEXT    NOT NULL,
    access_time  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    action       TEXT    DEFAULT 'read',
    is_sensitive INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS privilege_events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    username     TEXT    NOT NULL,
    change_type  TEXT,
    old_value    TEXT,
    new_value    TEXT,
    changed_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS risk_scores (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL,
    score         INTEGER DEFAULT 0,
    ai_score      INTEGER DEFAULT 0,
    risk_level    TEXT    DEFAULT 'low',
    calculated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    reason        TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT    NOT NULL,
    alert_type  TEXT,
    message     TEXT,
    severity    TEXT    DEFAULT 'medium',
    is_resolved INTEGER DEFAULT 0,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);