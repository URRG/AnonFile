# Synthetic demo and product-readiness plan

## Immediate demo acceptance criteria

The local development workbench must accept a synthetic UTF-8 `.txt`, `.csv`,
`.json`, or `.jsonl` file (or pasted text), identify bounded rules-based
findings, and display a transformed *demo preview*. It must disclose detector
coverage and limitations beside the preview. No preview may be called anonymous,
qualified, approved, exportable, or sellable. The preview endpoint is disabled
by default, requires an explicit development-only opt-in and processor token,
does not persist data, and remains unavailable in production mode. Existing
release, approval, candidate-custody, and buyer-delivery boundaries stay
unchanged. A local HTTP/UI integration test and full API/web suites are the
exit gate; a rendered-browser walkthrough is desirable when a browser is
available.

## Gaps after the synthetic demo

1. **Detector quality and coverage.** Collect representative, legally usable
   and independently annotated holdout corpora by source format, language,
   country, industry, and identifier family. Measure exact-span precision,
   recall and false negatives. Add configurable domain recognizers and
   validated models for free-text names, addresses, organizations, healthcare,
   business-sensitive context and indirect identifiers. Support documents,
   images, audio and other purchased-data formats only after their parsers and
   provenance are tested. Never infer completeness from a finite ruleset.
2. **Independent privacy and utility qualification.** Scan the *final*
   transformed artifact with independent methods, run linkage and
   re-identification attacks against realistic auxiliary data, test schema and
   task utility, and set source-specific thresholds and abstention rules.
   Evaluate every processor/model revision against a frozen holdout. A clean
   residual scan alone is not an anonymity proof.
3. **Supplier rights and governance.** Verify supplier organization and signer
   authority, preserve revocable and exact-scope rights evidence, settle when
   the supplier signs relative to processing and transfer, and bind rights,
   purpose, recipient, policy and output artifact at every admission/release
   gate. Legal sufficiency requires external review; a signature alone is not
   proof of permission to sell.
4. **Production data plane.** Wire the already tested PostgreSQL, encrypted
   object, key-service and worker components into one deployable lifecycle.
   Add OIDC, tenant isolation, hardened secrets and network controls,
   retention/deletion across replicas and backups, observability, incident
   recovery, migrations and operational runbooks. Keep production routes
   closed until the complete path is verified end to end.
5. **Controlled delivery and commercial validation.** Require independent
   approval of an immutable qualified artifact, recipient-bound publication,
   audit and revocation. Validate security and performance with design
   partners, external testing and documented acceptance criteria before
   handling customer data.

The synthetic preview is a presentation aid, not a shortcut through any of
these gates or authorization to upload actual company data.
