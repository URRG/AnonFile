# M46: version-pinned S3 ciphertext identity

M46 is an opt-in sibling of M32 for deployments that have already enabled and
tested provider object versioning.  It does not change M32, M38, M40, database
metadata, routes, or existing objects.

`S3VersionedCiphertextTransport` requires a non-null bounded `VersionId` in a
successful `PutObject` response.  It returns that opaque value with the
ciphertext digest, size, and deployment-owned `profile_id`.  Every `load` and
`recover` call requires the complete returned `VersionedStoredCiphertext`
identity, checks its profile and derived key before any S3 I/O, sends its
`VersionId` as S3's `VersionId`, and then checks the returned version's
publication marker, digest and size before returning any bytes.  This makes a
caller able to pin a provider object version rather than reading whichever
version is currently selected by a key.

The identifier is not an integrity hash: M32's SHA-256 checks remain required.
It is also not an immutability, deletion-prevention, retention, Object Lock,
legal-hold, provider-certification, or release-authorization claim.  Versioning
can permit later versions under the same key.  A later Object Lock profile must
separately prove its exact bucket/provider configuration, retention mode and
date, permissions, upload checksum, and version-specific post-write state.

The deployment-owned `profile_id` names the separately reviewed versioned
provider configuration; this code does not discover or configure a bucket.
Missing, `null`, malformed, or overlong version identifiers fail closed.  A
raw caller-supplied `VersionId` is never a public-request authorization input:
the future protected path must load both it and its profile identifier from
durable, immutable server-side evidence.  `VersionedStoredCiphertext` is a
validated value shape, not provenance by itself: callers can construct one, so
only its durable server-side record establishes that it belongs to a release.
The normal M32 path stays available for legacy data.  New release paths may
require this adapter only after they have that durable evidence; it is
deliberately outside M46.

M46 cannot recover an ambiguous `PutObject` outcome after its response was
lost: no trustworthy version identity exists in that case.  Its `recover`
method only re-reads a version identity that was already durably recorded by a
future server-owned control.  M38's existing marker/envelope recovery remains
unchanged and is not replaced by this slice.
