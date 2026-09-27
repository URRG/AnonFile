# D06 ephemeral graph adjudication prototype

`app.graph_adjudication` is a pure in-memory helper for synthetic fixtures.
It accepts only bounded opaque review IDs and the product's fixed graph
ontology. It can apply explicit accept/reject decisions, a person-identity
merge, and a split only when every non-rejected incident claim has an explicit
replacement assignment.

The returned summary contains aggregate action counts, relationship-type
counts, and fixed potential-conflict categories. It deliberately omits source
text, document IDs, node IDs, claim IDs, aliases, and evidence locations.

The current typed conflict signals are conservative review prompts:

- `POTENTIAL_MULTIPLE_WORKS_AT` for accepted employment links from one
  effective person to more than one organization.
- `POTENTIAL_MULTIPLE_ASSIGNED_TO` for accepted assignments from one project
  to more than one person.

Neither signal resolves a relationship, and neither assumes outside work or
multiple assignees are impossible. They require future reviewer adjudication.
Each source-free conflict record is explicitly marked
`UNRESOLVED_REVIEW_REQUIRED`.

Splits require an assignment for every non-rejected incident claim. Because an
assignment currently addresses a claim rather than an endpoint, a claim that
is incident to two split identities fails closed instead of overwriting one
endpoint. Similarly, an accepted person-to-person edge that would collapse to
a self-link after a merge fails closed.

Merges and splits cannot share a person: neither a split source nor a split
replacement may participate in a merge in the same call. This avoids inventing
an order or silently retaining a non-canonical replacement identity.

## Explicit limits

This prototype has no route, UI control, persistence, identity registry,
audit trail, authorization binding, revision/CAS behavior, or release effect.
Every invocation is ephemeral and must be discarded. It does not establish
real-world identity resolution, source correctness, evidence sufficiency, or
permission to release data.

## Revisioned identity overlay

`app.revisioned_graph_review` separately provides a trusted-server, in-process
review primitive for D06 identity overlays. It has no route, API contract,
storage adapter, durable claim, or release effect. Its merge and split actions
are optimistic-revision updates with a redacted public view and append-only
review audit.

A merge has exactly two *current* person members and chooses one of them as
the canonical current person. The snapshot's original claims and evidence
bindings are never rewritten. A merge fails closed if it would make any active
person-to-person relationship a self-link.

A split names current replacement person nodes and must provide exactly one
assignment for every active incident person endpoint. Each assignment contains
both the opaque claim ID and `source` or `target`; duplicates, omissions,
unrelated endpoints, and rejected identifiers fail closed. This endpoint-level
schema deliberately avoids assigning an entire person-to-person claim twice or
silently overwriting one side.

After every decision or overlay, the primitive recalculates its aggregate-only
multiple-affiliation and multiple-assignment prompts. These remain
`UNRESOLVED_REVIEW_REQUIRED`: overlays do not resolve conflicts, authorize a
release, or establish a real-world identity fact. Evidence bindings never
appear in the public view or overlay audit.
