CREATE TABLE IF NOT EXISTS threats (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    severity VARCHAR(16) NOT NULL DEFAULT 'unknown'
        CHECK (severity IN ('unknown', 'low', 'medium', 'high', 'critical')),
    threat_type VARCHAR(32) NOT NULL DEFAULT 'other'
        CHECK (threat_type IN ('other', 'trojan', 'worm', 'ransomware', 'spyware')),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS file_hashes (
    md5 VARCHAR(32) PRIMARY KEY CHECK (md5 ~ '^[0-9a-f]{32}$'),
    threat_id BIGINT NOT NULL REFERENCES threats(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS file_hashes_threat_id_idx ON file_hashes(threat_id);
