DROP TABLE IF EXISTS alerts;
CREATE TABLE alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    source_type TEXT NOT NULL,
    raw_message TEXT NOT NULL,
    severity TEXT NOT NULL,
    summary TEXT,
    recommendation TEXT,
    created_at TEXT NOT NULL
);

DROP TABLE IF EXISTS iocs;
CREATE TABLE iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    FOREIGN KEY(alert_id) REFERENCES alerts(id)
);
