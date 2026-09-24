# M44a exact-candidate-byte bridge

`app.candidate_publication_bridge` is a private-worker primitive that derives
an M42 `PublicationPayloadBinding` from the already validated
`CandidateArtifact`'s original encoded bytes. It accepts no release payload,
digest, byte count, serializer identifier, or JSON value. The sole serializer
is `binary-v1`, and structured output is the candidate artifact's existing
canonical JSON bytes rather than a decoded-and-reencoded value.

The bridge requires a `ReleaseCaseBinding` and a `PublicationIntent`. It
rejects drift between candidate artifact/run/policy and the case binding, or
between the intent request/policy commitments and the case binding. It returns
the exact bytes only through a representation-safe private-worker wrapper.

This is **not** publication authorization. The caller must first obtain a live
verified release case, M15/M18/M21 controls, and a server-owned authorized
destination plan. This module does not load a case, verify its signature,
sign M43, persist an intent, expose an API route, authorize a recipient, or
enable production workflows. In particular, a caller-supplied case binding or
destination plan is not trustworthy until a later server-side issuer derives
and verifies it from durable controls.
