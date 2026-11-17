-- Initial schema. Applied when PRAGMA user_version is below 1.

CREATE TABLE comments (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    page       TEXT    NOT NULL,
    parent_id  INTEGER REFERENCES comments(id) ON DELETE CASCADE,
    author     TEXT    NOT NULL,
    body       TEXT    NOT NULL,
    status     TEXT    NOT NULL DEFAULT 'visible'
               CHECK (status IN ('visible', 'pending', 'deleted')),
    created_at INTEGER NOT NULL,
    ip_hash    TEXT    NOT NULL
);

CREATE INDEX comments_page ON comments(page, status, created_at);
CREATE INDEX comments_parent ON comments(parent_id);

CREATE TABLE rate_events (
    ip_hash    TEXT    NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE INDEX rate_events_ip ON rate_events(ip_hash, created_at);
