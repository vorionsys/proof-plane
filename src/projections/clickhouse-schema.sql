--
-- ClickHouse Analytics Offload Schema
--
-- Designed for 100K-agent fleet analytics. Raw proof events flow from
-- CockroachDB (OLTP) into ClickHouse (OLAP) via CDC or batch export.
-- Materialized views pre-aggregate hourly and daily metrics for
-- sub-second dashboard queries at scale.
--
-- Retention policy:
--   90 days  — raw events (proof_events, trust_history)
--   1 year   — aggregated views (fleet_metrics_hourly, agent_metrics_daily)
--
-- Deployment: apply via clickhouse-client or migration tool.
-- All tables use ReplicatedMergeTree in production; drop the
-- Replicated prefix for single-node dev/test.

-- =========================================================================
-- 1. Raw Proof Events
-- =========================================================================

CREATE TABLE IF NOT EXISTS proof_events
(
    event_id         String,
    event_type       LowCardinality(String),
    correlation_id   String,
    agent_id         Nullable(String),
    payload          String,              -- JSON string
    previous_hash    Nullable(String),
    event_hash       String,
    event_hash3      Nullable(String),
    occurred_at      DateTime64(3, 'UTC'),
    recorded_at      DateTime64(3, 'UTC'),
    signed_by        Nullable(String),
    signature        Nullable(String),
    shadow_mode      LowCardinality(String) DEFAULT 'production',
    verification_id  Nullable(String),
    verified_at      Nullable(DateTime64(3, 'UTC')),

    -- Denormalized fields extracted from payload for fast filtering
    trust_score      Nullable(Float64),
    trust_band       Nullable(LowCardinality(String)),
    action_permitted Nullable(UInt8),     -- 0=denied, 1=permitted
    integrity_score  Nullable(Float64)
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(occurred_at)
ORDER BY (occurred_at, agent_id, event_id)
TTL toDateTime(occurred_at) + INTERVAL 90 DAY DELETE
SETTINGS index_granularity = 8192;

-- Secondary indexes for common query patterns
ALTER TABLE proof_events ADD INDEX idx_agent_id agent_id TYPE bloom_filter GRANULARITY 4;
ALTER TABLE proof_events ADD INDEX idx_event_type event_type TYPE set(0) GRANULARITY 1;
ALTER TABLE proof_events ADD INDEX idx_correlation_id correlation_id TYPE bloom_filter GRANULARITY 4;

-- =========================================================================
-- 2. Trust History (score changes over time)
-- =========================================================================

CREATE TABLE IF NOT EXISTS trust_history
(
    agent_id         String,
    previous_score   Float64,
    new_score        Float64,
    previous_band    LowCardinality(String),
    new_band         LowCardinality(String),
    reason           String,
    delta_id         String,
    integrity_score  Float64 DEFAULT 1.0,
    occurred_at      DateTime64(3, 'UTC'),
    recorded_at      DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(occurred_at)
ORDER BY (occurred_at, agent_id)
TTL toDateTime(occurred_at) + INTERVAL 90 DAY DELETE
SETTINGS index_granularity = 8192;

ALTER TABLE trust_history ADD INDEX idx_th_agent_id agent_id TYPE bloom_filter GRANULARITY 4;
ALTER TABLE trust_history ADD INDEX idx_th_band new_band TYPE set(0) GRANULARITY 1;

-- =========================================================================
-- 3. Fleet Metrics — Hourly (Materialized View)
-- =========================================================================
--
-- Pre-aggregates fleet-wide counters every hour for dashboard widgets.
-- Uses AggregatingMergeTree so partial aggregates merge correctly
-- across partitions and replicas.

CREATE TABLE IF NOT EXISTS fleet_metrics_hourly
(
    hour             DateTime,
    total_events     AggregateFunction(count, UInt64),
    unique_agents    AggregateFunction(uniq, String),
    denied_count     AggregateFunction(sum, UInt64),
    permitted_count  AggregateFunction(sum, UInt64),
    avg_trust_score  AggregateFunction(avg, Float64),
    min_trust_score  AggregateFunction(min, Float64),
    max_trust_score  AggregateFunction(max, Float64),
    avg_integrity    AggregateFunction(avg, Float64),
    incident_count   AggregateFunction(sum, UInt64),

    -- Tier distribution
    tier_0_count     AggregateFunction(sum, UInt64),
    tier_1_count     AggregateFunction(sum, UInt64),
    tier_2_count     AggregateFunction(sum, UInt64),
    tier_3_count     AggregateFunction(sum, UInt64),
    tier_4_count     AggregateFunction(sum, UInt64),
    tier_5_count     AggregateFunction(sum, UInt64),
    tier_6_count     AggregateFunction(sum, UInt64),
    tier_7_count     AggregateFunction(sum, UInt64)
)
ENGINE = AggregatingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (hour)
TTL hour + INTERVAL 1 YEAR DELETE;

CREATE MATERIALIZED VIEW IF NOT EXISTS fleet_metrics_hourly_mv
TO fleet_metrics_hourly
AS
SELECT
    toStartOfHour(occurred_at) AS hour,
    countState()                                                        AS total_events,
    uniqState(assumeNotNull(agent_id))                                  AS unique_agents,
    sumState(toUInt64(action_permitted = 0))                            AS denied_count,
    sumState(toUInt64(action_permitted = 1))                            AS permitted_count,
    avgState(assumeNotNull(trust_score))                                AS avg_trust_score,
    minState(assumeNotNull(trust_score))                                AS min_trust_score,
    maxState(assumeNotNull(trust_score))                                AS max_trust_score,
    avgState(assumeNotNull(integrity_score))                            AS avg_integrity,
    sumState(toUInt64(event_type = 'incident_detected'))                AS incident_count,
    sumState(toUInt64(trust_band = 'T0_SANDBOX'))                       AS tier_0_count,
    sumState(toUInt64(trust_band = 'T1_QUARANTINE'))                    AS tier_1_count,
    sumState(toUInt64(trust_band = 'T2_PROBATION'))                     AS tier_2_count,
    sumState(toUInt64(trust_band = 'T3_TRUSTED'))                       AS tier_3_count,
    sumState(toUInt64(trust_band = 'T4_VERIFIED'))                      AS tier_4_count,
    sumState(toUInt64(trust_band = 'T5_ESTABLISHED'))                   AS tier_5_count,
    sumState(toUInt64(trust_band = 'T6_PRIVILEGED'))                    AS tier_6_count,
    sumState(toUInt64(trust_band = 'T7_AUTONOMOUS'))                    AS tier_7_count
FROM proof_events
WHERE agent_id IS NOT NULL
GROUP BY hour;

-- =========================================================================
-- 4. Agent Metrics — Daily (Materialized View)
-- =========================================================================
--
-- Per-agent daily rollups for trend analysis and compliance reports.

CREATE TABLE IF NOT EXISTS agent_metrics_daily
(
    day              Date,
    agent_id         String,
    total_actions    AggregateFunction(count, UInt64),
    denied_actions   AggregateFunction(sum, UInt64),
    avg_trust_score  AggregateFunction(avg, Float64),
    min_trust_score  AggregateFunction(min, Float64),
    max_trust_score  AggregateFunction(max, Float64),
    avg_integrity    AggregateFunction(avg, Float64),
    min_integrity    AggregateFunction(min, Float64),
    incidents        AggregateFunction(sum, UInt64),
    escalations      AggregateFunction(sum, UInt64),
    last_event_type  AggregateFunction(argMax, String, DateTime64(3, 'UTC'))
)
ENGINE = AggregatingMergeTree()
PARTITION BY toYYYYMM(day)
ORDER BY (day, agent_id)
TTL day + INTERVAL 1 YEAR DELETE;

CREATE MATERIALIZED VIEW IF NOT EXISTS agent_metrics_daily_mv
TO agent_metrics_daily
AS
SELECT
    toDate(occurred_at)                                                 AS day,
    assumeNotNull(agent_id)                                             AS agent_id,
    countState()                                                        AS total_actions,
    sumState(toUInt64(action_permitted = 0))                            AS denied_actions,
    avgState(assumeNotNull(trust_score))                                AS avg_trust_score,
    minState(assumeNotNull(trust_score))                                AS min_trust_score,
    maxState(assumeNotNull(trust_score))                                AS max_trust_score,
    avgState(assumeNotNull(integrity_score))                            AS avg_integrity,
    minState(assumeNotNull(integrity_score))                            AS min_integrity,
    sumState(toUInt64(event_type = 'incident_detected'))                AS incidents,
    sumState(toUInt64(event_type = 'escalation_requested'))             AS escalations,
    argMaxState(event_type, occurred_at)                                AS last_event_type
FROM proof_events
WHERE agent_id IS NOT NULL
GROUP BY day, agent_id;

-- =========================================================================
-- 5. Convenience query views (non-materialized)
-- =========================================================================

-- Fleet dashboard: latest hourly metrics
CREATE OR REPLACE VIEW fleet_dashboard AS
SELECT
    hour,
    countMerge(total_events)    AS total_events,
    uniqMerge(unique_agents)    AS unique_agents,
    sumMerge(denied_count)      AS denied_count,
    sumMerge(permitted_count)   AS permitted_count,
    avgMerge(avg_trust_score)   AS avg_trust_score,
    avgMerge(avg_integrity)     AS avg_integrity,
    sumMerge(incident_count)    AS incident_count
FROM fleet_metrics_hourly
GROUP BY hour
ORDER BY hour DESC
LIMIT 168;  -- 7 days of hourly data

-- Agent health: daily per-agent summary
CREATE OR REPLACE VIEW agent_health AS
SELECT
    day,
    agent_id,
    countMerge(total_actions)   AS total_actions,
    sumMerge(denied_actions)    AS denied_actions,
    avgMerge(avg_trust_score)   AS avg_trust_score,
    minMerge(min_trust_score)   AS min_trust_score,
    maxMerge(max_trust_score)   AS max_trust_score,
    avgMerge(avg_integrity)     AS avg_integrity,
    minMerge(min_integrity)     AS min_integrity,
    sumMerge(incidents)         AS incidents,
    sumMerge(escalations)       AS escalations
FROM agent_metrics_daily
GROUP BY day, agent_id
ORDER BY day DESC, agent_id;

-- Integrity alerts: agents with low integrity in the last 24 hours
CREATE OR REPLACE VIEW integrity_alerts_24h AS
SELECT
    agent_id,
    min(integrity_score) AS min_integrity,
    avg(integrity_score) AS avg_integrity,
    count()              AS event_count,
    max(occurred_at)     AS last_seen
FROM proof_events
WHERE occurred_at >= now() - INTERVAL 24 HOUR
  AND agent_id IS NOT NULL
  AND integrity_score IS NOT NULL
  AND integrity_score < 0.7
GROUP BY agent_id
ORDER BY min_integrity ASC;
