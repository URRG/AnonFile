# D06 live graph adapter

`graph_live_adapter` is constructed producer-locally beside the server graph;
it is not authentication, persistence, or a durable key. It maps bounded
response-local edge IDs to transient `claim_N`/`doc_N` IDs and returns only a
source-free ephemeral summary. Empty public graphs create no adjudication
claims. Evidence is bounded, canonicalized, and checked against both endpoints.
