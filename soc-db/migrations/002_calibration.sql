-- Migration 002: analyst labels + recall-guaranteed threshold calibration.
-- Idempotent: safe to run on an existing socdb (the live VM) and on a fresh install.

-- The model's attack probability (needed to set a threshold; tp_confidence stores only max-class prob).
ALTER TABLE ai_analyses ADD COLUMN IF NOT EXISTS attack_score NUMERIC(7,6);

-- Ground truth supplied by a human analyst for a randomly sampled alert (calibration labels).
CREATE TABLE IF NOT EXISTS analyst_labels (
    alert_id    BIGINT PRIMARY KEY REFERENCES wazuh_alerts(alert_id),
    is_attack   BOOLEAN NOT NULL,
    labeled_by  TEXT NOT NULL DEFAULT 'analyst',
    labeled_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Single-row state: the threshold currently in force and whether it carries the recall guarantee.
CREATE TABLE IF NOT EXISTS calibration_state (
    id             SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    model_version  TEXT,
    threshold      DOUBLE PRECISION,           -- NULL when not certified
    certified      BOOLEAN NOT NULL DEFAULT FALSE,
    n_labeled      INTEGER NOT NULL DEFAULT 0,
    n_attacks      INTEGER NOT NULL DEFAULT 0,
    rho            NUMERIC(4,3) NOT NULL DEFAULT 0.900,
    delta          NUMERIC(4,3) NOT NULL DEFAULT 0.100,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO calibration_state (id) VALUES (1) ON CONFLICT DO NOTHING;
