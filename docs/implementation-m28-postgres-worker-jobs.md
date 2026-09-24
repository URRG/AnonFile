# M28 PostgreSQL leased worker jobs

`app.postgres_worker_jobs.PostgresLeasedWorkerJobs` is an un-wired,
metadata-only PostgreSQL adapter for durable leased work. Operators apply
`services/api/migrations/002_m28_postgres_worker_jobs.sql` explicitly before
using it. The adapter accepts a tenant reference and opaque `work_ref` only;
there is no payload, source/candidate/object bytes, object-store client,
configuration, route, or worker loop.

`enqueue` is tenant-scoped and idempotent only for the same attempt budget (a
replay with a changed budget fails closed). `claim` uses `clock_timestamp()`
and `FOR UPDATE OF anonflow_worker_jobs SKIP LOCKED`;
an expired lease is eligible for a later database-clock reclaim, increments
both delivery attempt and fencing epoch, and records the preceding claim in
the returned M22 `LeasedWorkerClaim`. Acknowledgement is a CAS on tenant,
work, live claim id and epoch, additionally requiring the database-clock lease
to still be unexpired. Thus a stale or expired worker receives `False` and
cannot complete newer work. Delivery is at least once, not exactly once.

The bounded default/max attempt count is 3/100. A job at its budget is left
unclaimed for operator inspection; this slice has no dead-letter queue,
backoff, priority/fairness guarantees beyond oldest eligible work per tenant,
cleanup, retry policy, auditing, worker authorization, row authentication,
backup/restore procedure, or poison-job remediation. `SKIP LOCKED` favors
throughput and can starve a continuously skipped row. Connection factory,
TLS/secrets, migrations, monitoring, authorization, and production enablement
remain caller/operator responsibilities.
