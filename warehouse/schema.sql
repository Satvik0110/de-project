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

-- Messages the warehouse writer could not store (bad JSON, missing field, value Postgres
-- rejects). Kept with their Kafka coordinates instead of crashing the writer on every
-- restart; replaying the same message is a no-op.
CREATE TABLE IF NOT EXISTS warehouse_rejects (
    topic        text        NOT NULL,
    partition    integer     NOT NULL,
    "offset"     bigint      NOT NULL,
    error        text        NOT NULL,
    payload      text,
    rejected_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (topic, partition, "offset")
);

CREATE INDEX IF NOT EXISTS alerts_rule_idx        ON alerts (rule_name, first_detected_at DESC);
CREATE INDEX IF NOT EXISTS incidents_last_seen_idx ON incidents (last_seen DESC);
CREATE INDEX IF NOT EXISTS metrics_at_idx          ON pipeline_metrics (at DESC);

-- ----------------------------------------------------------------- analytical views
-- Read-only views over the tables above, for the dashboard and ad-hoc SQL. Views (not
-- copies), so they are never stale and the writer has nothing extra to maintain.

-- Severity as a number, so views can take max() of it.
CREATE OR REPLACE FUNCTION severity_rank(s text) RETURNS int
    LANGUAGE sql IMMUTABLE AS $$ SELECT array_position(ARRAY['low','medium','high','critical'], s) $$;

-- Per attacker IP per hour: how many alerts, which rules, worst severity.
CREATE OR REPLACE VIEW hourly_ip_stats AS
SELECT date_trunc('hour', first_event_time)             AS hour,
       host(src_ip)                                     AS src_ip,
       count(*)                                         AS alerts,
       array_agg(DISTINCT rule_name ORDER BY rule_name) AS rules,
       (ARRAY['low','medium','high','critical'])[max(severity_rank(severity))] AS max_severity,
       sum(count)                                       AS evidence_events
FROM alerts
WHERE src_ip IS NOT NULL
GROUP BY 1, 2;

-- Per detection rule: volume, distinct attackers, detection latency.
CREATE OR REPLACE VIEW attack_type_breakdown AS
SELECT rule_name, technique, tactic,
       count(*)                                         AS alerts,
       count(DISTINCT entity)                           AS attackers,
       min(first_detected_at)                           AS first_seen,
       max(detected_at)                                 AS last_seen,
       percentile_cont(0.5)  WITHIN GROUP (ORDER BY detection_latency_ms) AS latency_p50_ms,
       percentile_cont(0.95) WITHIN GROUP (ORDER BY detection_latency_ms) AS latency_p95_ms
FROM alerts
GROUP BY rule_name, technique, tactic;

-- One row per attacker (an IP, or user:<name> for distributed attacks) across all incidents.
-- Filter on last_seen for "active" ones, e.g. WHERE last_seen > now() - interval '1 hour'.
CREATE OR REPLACE VIEW threat_actors AS
SELECT i.entity,
       (ARRAY['low','medium','high','critical'])[max(severity_rank(i.severity))] AS severity,
       count(*)                                         AS incidents,
       sum(i.alert_count)                               AS alerts,
       bool_or(cardinality(i.tactics) >= 2)             AS multi_stage,
       bool_or('brute_force_success' = ANY (i.rules))   AS compromised_account,
       min(i.first_seen)                                AS first_seen,
       max(i.last_seen)                                 AS last_seen
FROM incidents i
GROUP BY i.entity;
