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

## Explicit limits

This prototype has no route, UI control, persistence, identity registry,
audit trail, authorization binding, revision/CAS behavior, or release effect.
Every invocation is ephemeral and must be discarded. It does not establish
real-world identity resolution, source correctness, evidence sufficiency, or
permission to release data.
