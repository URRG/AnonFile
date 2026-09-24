-- M28 metadata-only durable worker jobs. Apply explicitly with a privileged
-- migration role; this does not enable worker routing or application startup.
BEGIN;

CREATE TABLE IF NOT EXISTS anonflow_worker_jobs (
    tenant_ref TEXT NOT NULL CHECK (tenant_ref ~ '^tenantref:v1:[A-Za-z0-9_-]{43}$'),
    work_ref TEXT NOT NULL CHECK (work_ref ~ '^workref:v1:[A-Za-z0-9_-]{43}$'),
    max_attempts INTEGER NOT NULL CHECK (max_attempts BETWEEN 1 AND 100),
    delivery_attempt INTEGER NOT NULL DEFAULT 0 CHECK (delivery_attempt BETWEEN 0 AND max_attempts),
    lease_epoch BIGINT NOT NULL DEFAULT 0 CHECK (lease_epoch >= 0),
    claim_id TEXT CHECK (claim_id IS NULL OR claim_id ~ '^workerclaim:v1:[A-Za-z0-9_-]{43}$'),
    worker_ref TEXT CHECK (worker_ref IS NULL OR worker_ref ~ '^workerref:v1:[A-Za-z0-9_-]{43}$'),
    leased_at TIMESTAMPTZ,
    lease_expires_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_ref, work_ref),
    CHECK ((claim_id IS NULL) = (worker_ref IS NULL)),
    CHECK ((claim_id IS NULL) = (leased_at IS NULL)),
    CHECK ((claim_id IS NULL) = (lease_expires_at IS NULL)),
    CHECK (claim_id IS NULL OR (lease_epoch > 0 AND delivery_attempt > 0 AND leased_at < lease_expires_at))
);

CREATE INDEX IF NOT EXISTS anonflow_worker_jobs_claimable_idx
    ON anonflow_worker_jobs (tenant_ref, created_at, work_ref)
    WHERE completed_at IS NULL;

COMMIT;
