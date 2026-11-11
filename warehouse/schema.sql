-- Data warehouse (FR3): curated, query-optimised tables. Raw events live in the Parquet lake.
-- Idempotent: safe to re-run.

-- One row per alert. The stream processor re-sends an alert (early -> escalated -> final)
-- under the same deterministic alert_id, so writes are upserts on it.
CREATE TABLE IF NOT EXISTS alerts (
    alert_id            uuid PRIMARY KEY,
    rule_name           text        NOT NULL,
    severity            text        NOT NULL,
    technique           text,
    tactic              text,
    entity              text        NOT NULL,
    src_ip              inet,
    username            text,
    dest_ip             inet,
    window_start        timestamptz NOT NULL,
    window_end          timestamptz NOT NULL,
    count               integer     NOT NULL,
    threshold           integer     NOT NULL,
    trigger             text        NOT NULL,         -- early | escalated | final
    first_event_time    timestamptz NOT NULL,
    last_event_time     timestamptz NOT NULL,
    first_detected_at   timestamptz NOT NULL,         -- set once, on the first (early) version
    detected_at         timestamptz NOT NULL,         -- latest version
    detection_latency_ms double precision,            -- of the first version
    sample_event_ids    uuid[]      NOT NULL DEFAULT '{}',
    incident_id         uuid,
    raw                 jsonb       NOT NULL
);
CREATE INDEX IF NOT EXISTS alerts_detected_idx ON alerts (first_detected_at DESC);
CREATE INDEX IF NOT EXISTS alerts_src_idx      ON alerts (src_ip);
CREATE INDEX IF NOT EXISTS alerts_incident_idx ON alerts (incident_id);

-- Alerts from one attacker, chained while they keep arriving within a gap (session window).
CREATE TABLE IF NOT EXISTS incidents (
    incident_id     uuid PRIMARY KEY,
    entity          text        NOT NULL,             -- attacker: an IP, or user:<name> for distributed attacks
    first_seen      timestamptz NOT NULL,
    last_seen       timestamptz NOT NULL,
    severity        text        NOT NULL,
    tactics         text[]      NOT NULL DEFAULT '{}',-- in order of first appearance
    rules           text[]      NOT NULL DEFAULT '{}',
    alert_count     integer     NOT NULL DEFAULT 0,
    updated_at      timestamptz NOT NULL DEFAULT now(),
    summary         text,
    summary_source  text,                             -- llm | template
    summarised_at   timestamptz
);
CREATE INDEX IF NOT EXISTS incidents_entity_idx ON incidents (entity, last_seen DESC);

-- Per tumbling window and source type, whether or not anything alerted.
CREATE TABLE IF NOT EXISTS aggregates (
    window_start  timestamptz NOT NULL,
    window_end    timestamptz NOT NULL,
    source_type   text        NOT NULL,
    event_count   integer     NOT NULL,
    unique_ips    integer     NOT NULL,
    unique_users  integer     NOT NULL,
    success_count integer     NOT NULL,
    fail_count    integer     NOT NULL,
    denied_count  integer     NOT NULL,
    PRIMARY KEY (window_start, source_type)
);

-- Pipeline health snapshots from the processor.
CREATE TABLE IF NOT EXISTS pipeline_metrics (
    at                timestamptz PRIMARY KEY,
    events_per_s      double precision,
    consumer_lag      integer,
    watermark_delay_s double precision,
    latency_p50_ms    double precision,
    latency_p95_ms    double precision,
    latency_p99_ms    double precision,
    raw               jsonb NOT NULL
);

-- Ground truth from the attack simulator. Never read by the detection path;
-- only by the scoreboard, to grade detection.
CREATE TABLE IF NOT EXISTS campaigns (
    campaign_id     uuid PRIMARY KEY,
    scenario        text        NOT NULL,
    attacker_ips    inet[]      NOT NULL,
    target_user     text,
    expected_rules  text[]      NOT NULL,
    started_at      timestamptz NOT NULL,
    ended_at        timestamptz,
    requests        integer
);
