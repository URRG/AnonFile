# M47a1 PostgreSQL negative privacy fences

M47a1 adds a small PostgreSQL-only denial ledger for an opaque subject reference
within an opaque tenant. The baseline `NONE` records only the absence of a
negative state in this ledger. It is **not** consent, lawful basis, eligibility,
permission to process, or permission to publish.

`OPT_OUT`, `WITHDRAWN`, and `QUARANTINED` are terminal, append-only states. No
operation clears or replaces a negative fence. Subject and event identifiers are
opaque, validated, and no source, candidate, or personal data is stored here.

A future in-transaction finalizer may call `lock_none` only in an active
PostgreSQL **READ COMMITTED** transaction, retain the subject-row lock through
its own mutation, and perform the check immediately before commit. Writers use
the same stable row lock; consequently the post-lock latest-fence query sees a
fresh statement snapshot after a concurrent terminal writer commits. This is a
negative kill switch only: every positive legal, privacy, and release control
remains independently required and unimplemented.

Migration `013_m47a1_negative_privacy_fences.sql` is rerunnable. It is not wired
to an API route, issuer, development store, candidate data path, or release path.
