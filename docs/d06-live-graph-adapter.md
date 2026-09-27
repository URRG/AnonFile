# D06 live graph adapter

`graph_live_adapter` accepts only the server-produced current-batch graph and
current batch document-ID membership, maps response-local edge IDs to bounded
`claim_N`/`doc_N` prototype IDs, and returns the source-free ephemeral summary.
It has no route, persistence, client-submitted graph input, durable key, or
release effect. Evidence values are checked only for current-batch membership.
