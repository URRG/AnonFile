# M48b3 processing-run lineage

M48b3 adds a PostgreSQL-only, inert lineage record that binds one opaque
`processingrunref:v1` to exact immutable M48b1 source and M48b2 policy/method
snapshot metadata. It does not load or process bytes, schedule workers, expose
an API, or authorize release.

`ProcessingRunLineage` is canonical JSON under the domain separator
`anonflow-processing-run-lineage:v1:\0`. Its digest covers the tenant and run
references, both parent snapshot digests and references, copied source content
and provenance digests, copied policy/output-schema digests, and expiry.

Creation runs in one READ COMMITTED transaction. It locks the M45a3 tenant
identity first, the source snapshot second, and the policy/method snapshot
third; it verifies the active generation, every copied value, both parent
expiries, and PostgreSQL's second-resolution clock both before insertion and
again before commit. A lineage expiry must not outlast either parent.

Rows are immutable. Each run has a deferred generation-zero `ACTIVE` baseline
fence and can receive exactly one terminal `QUARANTINED`, `REVOKED`, or
`EXPIRED` fence. SQL triggers lock and require live source and policy fences,
enforce the parent-locking transition state machine, whole-second timestamps,
and early `EXPIRED` rejection. The public
`lock_active` method retains tenant/source/policy/run locks for a future
consumer's mutation.

The policy/method table stores its canonical component fields but not its
derived snapshot digest. Consequently, SQL directly validates its stored
policy and output-schema copies, while the adapter's live locked
`PolicyMethodSnapshot` comparison is the authority for the exact derived
`policy_method_snapshot_digest`. A forged SQL row therefore cannot pass
`create` or `lock_active` when the authoritative policy snapshot is supplied.
