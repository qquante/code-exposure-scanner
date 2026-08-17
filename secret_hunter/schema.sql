CREATE TABLE IF NOT EXISTS repositories (
    id BIGSERIAL PRIMARY KEY,
    host TEXT NOT NULL DEFAULT 'github.com',
    owner TEXT NOT NULL,
    name TEXT NOT NULL,
    full_name TEXT NOT NULL UNIQUE,
    html_url TEXT NOT NULL,
    is_public BOOLEAN NOT NULL DEFAULT TRUE,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id BIGSERIAL PRIMARY KEY,
    mode TEXT NOT NULL CHECK (mode IN ('search', 'repository', 'history', 'ingest')),
    scope TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'running'
        CHECK (status IN ('running', 'completed', 'partial', 'failed')),
    jobs_created INTEGER NOT NULL DEFAULT 0,
    findings_created INTEGER NOT NULL DEFAULT 0,
    errors INTEGER NOT NULL DEFAULT 0,
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS scan_jobs (
    id BIGSERIAL PRIMARY KEY,
    run_id BIGINT REFERENCES scan_runs(id) ON DELETE SET NULL,
    kind TEXT NOT NULL CHECK (kind IN (
        'github_search', 'fetch_blob', 'scan_history', 'scan_ingested_file',
        'enrich_repository_candidate'
    )),
    natural_key TEXT NOT NULL UNIQUE,
    payload JSONB NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    priority SMALLINT NOT NULL DEFAULT 0,
    attempts SMALLINT NOT NULL DEFAULT 0,
    max_attempts SMALLINT NOT NULL DEFAULT 5,
    available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    lease_owner TEXT,
    leased_until TIMESTAMPTZ,
    last_error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    CHECK (jsonb_typeof(payload) = 'object')
);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_claim
    ON scan_jobs (status, available_at, priority DESC, id);

CREATE TABLE IF NOT EXISTS findings (
    id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    fingerprint CHAR(64) NOT NULL,
    fingerprint_key_id TEXT NOT NULL,
    type_id TEXT NOT NULL,
    platform TEXT NOT NULL,
    category TEXT NOT NULL,
    environment TEXT NOT NULL DEFAULT 'unknown'
        CHECK (environment IN ('live', 'test', 'temporary', 'unknown')),
    risk TEXT NOT NULL CHECK (risk IN ('critical', 'high', 'medium', 'low')),
    confidence TEXT NOT NULL DEFAULT 'medium'
        CHECK (confidence IN ('high', 'medium', 'low')),
    secret_hint TEXT NOT NULL,
    validation_status TEXT NOT NULL DEFAULT 'not_checked'
        CHECK (validation_status IN (
            'not_checked', 'format_valid', 'provider_active', 'provider_inactive', 'unknown'
        )),
    status TEXT NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'notified', 'resolved', 'false_positive', 'accepted_risk')),
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (repository_id, type_id, fingerprint, fingerprint_key_id)
);

CREATE INDEX IF NOT EXISTS idx_findings_filters
    ON findings (status, risk, platform, category, last_seen DESC);

CREATE TABLE IF NOT EXISTS finding_locations (
    id BIGSERIAL PRIMARY KEY,
    finding_id BIGINT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    source_kind TEXT NOT NULL CHECK (source_kind IN ('code', 'history', 'trufflehog', 'ingest')),
    path TEXT NOT NULL DEFAULT '',
    branch TEXT NOT NULL DEFAULT '',
    commit_sha TEXT NOT NULL DEFAULT '',
    blob_sha TEXT NOT NULL DEFAULT '',
    line_start INTEGER NOT NULL DEFAULT 0 CHECK (line_start >= 0),
    line_end INTEGER NOT NULL DEFAULT 0 CHECK (line_end >= 0),
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (finding_id, source_kind, path, branch, commit_sha, blob_sha, line_start)
);

CREATE TABLE IF NOT EXISTS notification_outbox (
    id BIGSERIAL PRIMARY KEY,
    finding_id BIGINT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    repository_id BIGINT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    channel TEXT NOT NULL DEFAULT 'private_report'
        CHECK (channel IN ('private_report', 'public_contact_issue')),
    status TEXT NOT NULL DEFAULT 'pending_review'
        CHECK (status IN (
            'pending_review', 'approved', 'rejected', 'sending', 'sent',
            'needs_contact', 'failed'
        )),
    idempotency_key TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    private_body TEXT NOT NULL,
    public_body TEXT NOT NULL,
    approved_by TEXT,
    approved_at TIMESTAMPTZ,
    sent_at TIMESTAMPTZ,
    external_url TEXT,
    last_error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (finding_id, channel)
);

CREATE INDEX IF NOT EXISTS idx_notification_review
    ON notification_outbox (status, created_at, id);

DROP INDEX IF EXISTS idx_notification_active_repo;

CREATE UNIQUE INDEX idx_notification_active_repo
    ON notification_outbox (repository_id, channel)
    WHERE status IN (
        'pending_review', 'approved', 'rejected', 'sending', 'needs_contact', 'failed'
    );

CREATE TABLE IF NOT EXISTS notification_findings (
    notification_id BIGINT NOT NULL REFERENCES notification_outbox(id) ON DELETE CASCADE,
    finding_id BIGINT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    PRIMARY KEY (notification_id, finding_id)
);

CREATE TABLE IF NOT EXISTS rate_limit_buckets (
    bucket_key TEXT PRIMARY KEY,
    window_started_at TIMESTAMPTZ NOT NULL,
    used INTEGER NOT NULL DEFAULT 0 CHECK (used >= 0)
);

CREATE TABLE IF NOT EXISTS audit_events (
    id BIGSERIAL PRIMARY KEY,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id BIGINT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (jsonb_typeof(metadata) = 'object')
);

CREATE TABLE IF NOT EXISTS discovery_checkpoints (
    collector_key TEXT PRIMARY KEY,
    etag TEXT NOT NULL DEFAULT '',
    last_event_id TEXT NOT NULL DEFAULT '',
    next_poll_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_polled_at TIMESTAMPTZ,
    lease_owner TEXT,
    leased_until TIMESTAMPTZ,
    last_error TEXT NOT NULL DEFAULT '',
    gap_count INTEGER NOT NULL DEFAULT 0 CHECK (gap_count >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS discovery_windows (
    id BIGSERIAL PRIMARY KEY,
    collector_key TEXT NOT NULL REFERENCES discovery_checkpoints(collector_key)
        ON DELETE CASCADE,
    window_start TIMESTAMPTZ NOT NULL,
    window_end TIMESTAMPTZ NOT NULL,
    first_completed_at TIMESTAMPTZ,
    reconciled_at TIMESTAMPTZ,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    source_items_seen INTEGER NOT NULL DEFAULT 0 CHECK (source_items_seen >= 0),
    repositories_seen INTEGER NOT NULL DEFAULT 0 CHECK (repositories_seen >= 0),
    request_count INTEGER NOT NULL DEFAULT 0 CHECK (request_count >= 0),
    last_error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (collector_key, window_start, window_end),
    CHECK (window_end > window_start)
);

CREATE INDEX IF NOT EXISTS idx_discovery_windows_due
    ON discovery_windows (collector_key, next_attempt_at, window_end DESC)
    WHERE reconciled_at IS NULL;


CREATE TABLE IF NOT EXISTS discovery_candidates (
    id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    github_event_id TEXT NOT NULL UNIQUE,
    github_repository_id BIGINT NOT NULL UNIQUE,
    event_created_at TIMESTAMPTZ NOT NULL,
    repository_created_at TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'pending_metadata'
        CHECK (status IN (
            'pending_metadata', 'pending_review', 'filtered', 'unavailable',
            'scan_queued', 'rejected'
        )),
    language TEXT,
    size_kb INTEGER CHECK (size_kb IS NULL OR size_kb >= 0),
    is_fork BOOLEAN,
    is_archived BOOLEAN,
    is_disabled BOOLEAN,
    default_branch TEXT NOT NULL DEFAULT '',
    filter_reason TEXT NOT NULL DEFAULT '',
    metadata_checked_at TIMESTAMPTZ,
    authorization_reference TEXT NOT NULL DEFAULT '',
    authorized_by TEXT,
    authorized_at TIMESTAMPTZ,
    scan_job_id BIGINT REFERENCES scan_jobs(id) ON DELETE SET NULL,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_discovery_candidates_review
    ON discovery_candidates (status, event_created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_discovery_candidates_retention
    ON discovery_candidates (status, updated_at, id);

-- Migracoes idempotentes para bancos criados antes do adaptador de ingestao.
ALTER TABLE scan_runs DROP CONSTRAINT IF EXISTS scan_runs_mode_check;
ALTER TABLE scan_runs ADD CONSTRAINT scan_runs_mode_check
    CHECK (mode IN ('search', 'repository', 'history', 'ingest'));

ALTER TABLE scan_jobs DROP CONSTRAINT IF EXISTS scan_jobs_kind_check;
ALTER TABLE scan_jobs ADD CONSTRAINT scan_jobs_kind_check
    CHECK (kind IN (
        'github_search', 'fetch_blob', 'scan_history', 'scan_ingested_file',
        'enrich_repository_candidate'
    ));

ALTER TABLE finding_locations
    DROP CONSTRAINT IF EXISTS finding_locations_source_kind_check;
ALTER TABLE finding_locations ADD CONSTRAINT finding_locations_source_kind_check
    CHECK (source_kind IN ('code', 'history', 'trufflehog', 'ingest'));
