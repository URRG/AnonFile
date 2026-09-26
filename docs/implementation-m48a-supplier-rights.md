# M48a supplier rights assertion foundation

The data supplier is the party expected to attest that a referenced agreement
permits a specific dataset, buyer, recipient, purpose, and processing mode.
M48a defines an exact-scope, domain-separated Ed25519 statement and adds the
closed `SUPPLIER_RIGHTS_ATTESTER` public-key role. The statement also binds a
supplier organization, signer actor/key, source-dataset digest, candidate
custody reference and intent digest, contract reference/digest, validity window,
and nonce. Its first version permits **no onward transfer**; an affirmative
transfer requires a later schema with exact transferee and conditions binding.

Signature verification authenticates only the signed assertion against a
supplied public key. It is **not** proof that the signer represents the named
supplier, that the contract exists or is legally sufficient, or that the
dataset may be sold. The current verifier accepts a constructed key object, so
it must not be used as an admission or release authorization. There is no
supplier provisioning flow, assertion persistence or revocation, API route,
private-key loader, upload, or release capability in this milestone.

Before a production admission path can use this evidence, an administrator must
bind the supplier organization to an authorized signer through verified,
revocable provisioning evidence. The admission transaction must lock the
registry-loaded key and its live fence, supplier identity, assertion state,
candidate custody and rights/policy controls; match the signed fields to the
durable transaction; and recheck expiry using the PostgreSQL clock before
commit. The custody-intent digest commits to artifact, run, policy, schema and
provenance digests only if that exact durable intent is loaded and compared.
None of those later checks are implied by a successful M48a signature check.
