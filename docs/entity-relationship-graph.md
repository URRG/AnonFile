# Evidence-backed entity graph for the synthetic workbench

An entity-relationship diagram normally describes a *schema* (the kinds of
entities and permitted links). The reviewer needs an *instance graph* of the
particular batch: typed nodes, directed and named links, and the document
evidence for every displayed link. A mail log is only one possible edge type.
The graph must not present an inferred affiliation as an observed fact.

## Small, explicit ontology

| Node | Meaning | Display label |
| --- | --- | --- |
| Person | One batch-local identity hypothesis | Consistent person surrogate, or `Source retained` after exclusion |
| Organization | An explicitly named company or team | Batch-local organization surrogate |
| Project | An explicitly named incident or project | Batch-local project surrogate |
| Document | Source of evidence, not a social actor | Document number and kind in the evidence panel |

| Directed edge | Semantics | Minimum evidence |
| --- | --- | --- |
| `WORKS_AT`: Person → Organization | Employment/affiliation claim | An explicit `company`/`employer` field pair or labelled signature; email domain alone is insufficient |
| `ASSISTANT_TO`: Person → Person | Assistant role for a named person | A direct role phrase or paired structured fields; `Cc` is insufficient |
| `ASSISTANT_FOR`: Person → Organization | Assistant role explicitly for a company | A direct role phrase or paired structured fields; a generic job title is insufficient |
| `CLIENT_OF`: Person → Organization | Client relationship | An explicit client/organization field pair or phrase with both parties; a received email is insufficient |
| `WORKS_ON`: Person → Project | Assigned work | An explicit assignee/project field or direct role statement; mentioning an incident is insufficient |
| `ASSIGNED_TO`: Project → Person | Project assignment claim | An explicit project/assignee field pair or direct assignment statement |
| `SENT_TO`: Person → Person | Message delivery | A parsed `From`/`To` header with bound identities; this is an event, not evidence of employment or friendship |

The edge direction has meaning; inverse wording is a presentation choice, not
a second edge. Repeated evidence for the same subject–predicate–object triple
is grouped under one edge. Separate contradictory claims are retained for
review instead of silently resolved. Labels are batch-local pseudonyms; the
graph itself must not echo source names, addresses, domains, private project
names, or raw evidence snippets.

## Extraction and review contract

1. Parse each source with format-specific boundaries (mail headers, signature
   blocks, calendar fields, structured records). For PDF/image text, retain OCR
   provenance and mark it as unverified.
2. Bind a mention to a batch-local identity only with explicit evidence. Exact
   name equality can still merge homonyms, and an email address can belong to
   more than one person over time. Ambiguous bindings abstain.
3. Apply narrowly defined relation rules to explicit subject and object spans.
   Do not derive `WORKS_AT` from an email domain or `CLIENT_OF` from a `To`
   header. Do not run a free-form model and treat its prose as evidence.
4. Record the source document ID, extraction rule, and bounded field for
   each edge. The UI offers an evidence inspector and a route back to the
   source comparison. Text evidence can navigate to a validated source span;
   media evidence can show bounded approximate OCR-line boxes on one verified
   source page or explicitly abstains. These locators are not pixel-precise
   relationship proof, OCR coverage evidence, or a correctness score.
5. Render role/affiliation links first in a spatial node-link map. Show mail
   traffic only by opt-in toggle so a long thread does not bury the useful
   relationships. Provide zoom, pan, fit, keyboard-operable selection and a
   textual list equivalent.
6. Support reviewer accept/reject/merge/split in a future adjudication step.
   The current synthetic demo may display deterministic evidence but must not
   claim that cross-document identity resolution is complete.

The rule set and aliasing both need evaluation on an independently labelled
holdout. Measure node linking precision/recall, relation precision/recall *by
type*, evidence-location agreement, abstentions, contradictory roles, OCR
propagation failures, and leakage of source identifiers into graph payloads.
No single graph completeness score can certify a release.

This follows the property-graph distinction between typed nodes, directed
relationships and relationship properties in [Neo4j's graph model](https://neo4j.com/docs/getting-started/appendix/graphdb-concepts/).
Document-level evidence is provenance rather than a social edge; the [W3C
PROV model](https://www.w3.org/TR/prov-primer/) is a useful vocabulary for
keeping provenance separate from the relation claim. The graph layout may be
hierarchical (direction-preserving) or force-based; [Neo4j's graph dashboard
documentation](https://neo4j.com/docs/aura/dashboards/visualizations/graph/)
describes both. Our small demo should prefer a stable, readable layout over
an animated force simulation.
