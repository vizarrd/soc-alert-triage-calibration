-- =====================================================================
-- AI-SOC Incident Lifecycle Database Schema
-- PostgreSQL 14+
--
-- Tracks the full pipeline: Wazuh alert -> AI decision -> incident ->
-- response action. Designed to be populated by the integration script
-- (step 7) that pulls alerts from Wazuh, runs them through the trained
-- models (wazuh_tp_classifier.joblib / wazuh_severity_classifier.joblib),
-- and writes results here.
--
-- Run on the existing ctf-bugbounty VM (install postgres there) --
-- no new GCP resource needed, so it only costs anything while that
-- VM is running, same as the rest of the project.
-- =====================================================================

-- ---------------------------------------------------------------------
-- assets: every host Wazuh monitors (agents), plus metadata used for
-- context (an alert on a production DB server matters more than the
-- same alert on a scratch VM).
-- ---------------------------------------------------------------------
CREATE TABLE assets (
    asset_id        SERIAL PRIMARY KEY,
    wazuh_agent_id   TEXT UNIQUE NOT NULL,      -- Wazuh's own agent id, e.g. '001'
    hostname         TEXT NOT NULL,
    ip_address       TEXT,
    asset_type       TEXT NOT NULL DEFAULT 'server',  -- server / workstation / demo-target
    criticality      TEXT NOT NULL DEFAULT 'medium' CHECK (criticality IN ('low','medium','high','critical')),
    owner            TEXT,                      -- who's responsible for this asset
    is_active        BOOLEAN NOT NULL DEFAULT TRUE,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------
-- analysts: SOC users who can be assigned incidents / take actions.
-- Minimal for a demo -- one or two rows is enough.
-- ---------------------------------------------------------------------
CREATE TABLE analysts (
    analyst_id       SERIAL PRIMARY KEY,
    name             TEXT NOT NULL,
    email            TEXT UNIQUE,
    role             TEXT NOT NULL DEFAULT 'analyst' CHECK (role IN ('analyst','lead','admin')),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------
-- wazuh_alerts: raw alerts as received from Wazuh, one row per alert.
-- full_raw keeps the complete original JSON for audit/replay; the
-- other columns are the parsed-out fields the AI models actually use
-- (same shape as the training dataset's columns, on purpose --
-- keeps inference input identical to training input).
-- ---------------------------------------------------------------------
CREATE TABLE wazuh_alerts (
    alert_id         BIGSERIAL PRIMARY KEY,
    wazuh_alert_uid  TEXT UNIQUE,               -- Wazuh's own alert id, if present
    asset_id         INTEGER NOT NULL REFERENCES assets(asset_id),
    received_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    event_timestamp  TIMESTAMPTZ NOT NULL,
    rule_id          TEXT NOT NULL,
    rule_level       INTEGER NOT NULL,
    rule_description TEXT,
    rule_groups      TEXT,                      -- pipe-separated, matches dataset format
    mitre_id         TEXT,
    mitre_tactic     TEXT,
    mitre_technique  TEXT,
    decoder          TEXT,
    src_ip           TEXT,
    full_log         TEXT,
    full_raw         JSONB,                      -- complete original Wazuh alert JSON
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_alerts_asset ON wazuh_alerts(asset_id);
CREATE INDEX idx_alerts_received ON wazuh_alerts(received_at);
CREATE INDEX idx_alerts_rule_level ON wazuh_alerts(rule_level);
CREATE INDEX idx_alerts_src_ip ON wazuh_alerts(src_ip);

-- ---------------------------------------------------------------------
-- ai_analyses: the AI Decision Engine's output for one alert. One row
-- per (alert, model_version) so re-scoring with a retrained model
-- doesn't destroy history -- you can compare old vs new verdicts.
-- ---------------------------------------------------------------------
CREATE TABLE ai_analyses (
    analysis_id        BIGSERIAL PRIMARY KEY,
    alert_id           BIGINT NOT NULL REFERENCES wazuh_alerts(alert_id),
    model_version       TEXT NOT NULL,             -- e.g. 'tp_v1+sev_v1', tie to a git tag/date
    is_true_positive    BOOLEAN NOT NULL,
    tp_confidence        NUMERIC(4,3) NOT NULL,      -- 0.000-1.000
    severity            TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
    priority            SMALLINT NOT NULL CHECK (priority BETWEEN 1 AND 5),
    recommended_action   TEXT,                       -- free text or an action_type code, e.g. 'block_ip'
    analyzed_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_analyses_alert ON ai_analyses(alert_id);
CREATE INDEX idx_analyses_priority ON ai_analyses(priority);

-- ---------------------------------------------------------------------
-- incidents: a real security event, possibly correlated from multiple
-- alerts (e.g. 40+ brute-force alerts + 1 successful-login alert =
-- one incident: "SSH compromise of svc_audit"). This is the unit an
-- analyst actually works, not the raw alert.
-- ---------------------------------------------------------------------
CREATE TABLE incidents (
    incident_id      SERIAL PRIMARY KEY,
    title            TEXT NOT NULL,
    asset_id         INTEGER NOT NULL REFERENCES assets(asset_id),
    severity         TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
    priority         SMALLINT NOT NULL CHECK (priority BETWEEN 1 AND 5),
    status           TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','investigating','contained','resolved','closed','false_positive')),
    assigned_to      INTEGER REFERENCES analysts(analyst_id),
    summary          TEXT,                      -- AI-generated or analyst-written narrative
    opened_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    closed_at        TIMESTAMPTZ
);

CREATE INDEX idx_incidents_status ON incidents(status);
CREATE INDEX idx_incidents_asset ON incidents(asset_id);

-- ---------------------------------------------------------------------
-- incident_alerts: many-to-many join -- one incident can be built from
-- several alerts, and (rarely) one alert could be relevant to more
-- than one incident timeline.
-- ---------------------------------------------------------------------
CREATE TABLE incident_alerts (
    incident_id      INTEGER NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    alert_id         BIGINT NOT NULL REFERENCES wazuh_alerts(alert_id),
    linked_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (incident_id, alert_id)
);

-- ---------------------------------------------------------------------
-- actions: every response action, automated or manual, tied to an
-- incident. Keeps the "what did we actually do about it" audit trail
-- the user's original architecture asked for.
-- ---------------------------------------------------------------------
CREATE TABLE actions (
    action_id        SERIAL PRIMARY KEY,
    incident_id      INTEGER NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    action_type      TEXT NOT NULL,              -- e.g. 'block_ip', 'disable_account', 'notify_analyst', 'manual_note'
    description      TEXT,
    taken_by         TEXT NOT NULL DEFAULT 'ai_engine' CHECK (taken_by IN ('ai_engine','analyst','system')),
    analyst_id       INTEGER REFERENCES analysts(analyst_id),  -- set only when taken_by = 'analyst'
    status           TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','completed','failed','skipped')),
    taken_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_actions_incident ON actions(incident_id);

-- ---------------------------------------------------------------------
-- Keep incidents.updated_at current whenever the row changes.
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION touch_incident_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_incidents_updated_at
BEFORE UPDATE ON incidents
FOR EACH ROW EXECUTE FUNCTION touch_incident_updated_at();

-- ---------------------------------------------------------------------
-- Seed data: the two VMs already in play, so the integration script
-- has real asset_id values to reference on day one.
-- ---------------------------------------------------------------------
INSERT INTO assets (wazuh_agent_id, hostname, ip_address, asset_type, criticality, owner) VALUES
    ('000', 'ctf-bugbounty', '10.128.0.2', 'server', 'high', 'maro'),
    ('001', 'soc-target',    '10.128.0.3', 'demo-target', 'critical', 'maro');

INSERT INTO analysts (name, email, role) VALUES
    ('Admin', NULL, 'admin');
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
