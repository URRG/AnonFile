-- D06 shared, source-free review journal. This is not a release or audit anchor.
BEGIN;
CREATE TABLE IF NOT EXISTS anonflow_graph_review_snapshots (
 tenant_ref TEXT NOT NULL CHECK (tenant_ref ~ '^tenantref:v1:[A-Za-z0-9_-]{43}$'),
 snapshot_ref TEXT NOT NULL UNIQUE CHECK (snapshot_ref ~ '^graphsnap:v1:[A-Za-z0-9_-]{43}$'),
 snapshot JSONB NOT NULL,
 snapshot_digest TEXT NOT NULL CHECK (snapshot_digest ~ '^sha256:[0-9a-f]{64}$'),
 expires_at TIMESTAMPTZ NOT NULL,
 PRIMARY KEY (tenant_ref,snapshot_ref),
 CHECK (octet_length(snapshot::text) <= 131072)
);
CREATE TABLE IF NOT EXISTS anonflow_graph_review_events (
 tenant_ref TEXT NOT NULL,
 snapshot_ref TEXT NOT NULL,
 revision INTEGER NOT NULL CHECK (revision BETWEEN 1 AND 200),
 action JSONB NOT NULL,
 previous_digest TEXT NOT NULL CHECK (previous_digest ~ '^sha256:[0-9a-f]{64}$'),
 event_digest TEXT NOT NULL CHECK (event_digest ~ '^sha256:[0-9a-f]{64}$'),
 PRIMARY KEY (tenant_ref,snapshot_ref,revision),
 FOREIGN KEY (tenant_ref,snapshot_ref) REFERENCES anonflow_graph_review_snapshots(tenant_ref,snapshot_ref)
  ON UPDATE RESTRICT ON DELETE RESTRICT,
 CHECK (octet_length(action::text) <= 8192)
);
CREATE OR REPLACE FUNCTION anonflow_graph_review_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'graph review records are immutable'; END; $$;
DROP TRIGGER IF EXISTS anonflow_graph_review_snapshots_immutable ON anonflow_graph_review_snapshots;
CREATE TRIGGER anonflow_graph_review_snapshots_immutable BEFORE UPDATE OR DELETE ON anonflow_graph_review_snapshots
 FOR EACH ROW EXECUTE FUNCTION anonflow_graph_review_immutable();
DROP TRIGGER IF EXISTS anonflow_graph_review_events_immutable ON anonflow_graph_review_events;
CREATE TRIGGER anonflow_graph_review_events_immutable BEFORE UPDATE OR DELETE ON anonflow_graph_review_events
 FOR EACH ROW EXECUTE FUNCTION anonflow_graph_review_immutable();
CREATE OR REPLACE FUNCTION anonflow_graph_review_event_order() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE last_revision INTEGER; last_digest TEXT; parent_expiry TIMESTAMPTZ; parent_digest TEXT;
BEGIN
 SELECT expires_at,snapshot_digest INTO parent_expiry,parent_digest FROM anonflow_graph_review_snapshots
  WHERE tenant_ref=NEW.tenant_ref AND snapshot_ref=NEW.snapshot_ref FOR UPDATE;
 IF NOT FOUND OR parent_expiry <= clock_timestamp() THEN RAISE EXCEPTION 'graph review unavailable'; END IF;
 SELECT revision,event_digest INTO last_revision,last_digest FROM anonflow_graph_review_events
  WHERE tenant_ref=NEW.tenant_ref AND snapshot_ref=NEW.snapshot_ref ORDER BY revision DESC LIMIT 1;
 IF NEW.revision <> COALESCE(last_revision,0)+1 OR NEW.previous_digest <> COALESCE(last_digest,parent_digest)
 THEN RAISE EXCEPTION 'graph review revision or chain mismatch'; END IF;
 RETURN NEW;
END; $$;
DROP TRIGGER IF EXISTS anonflow_graph_review_events_order ON anonflow_graph_review_events;
CREATE TRIGGER anonflow_graph_review_events_order BEFORE INSERT ON anonflow_graph_review_events
 FOR EACH ROW EXECUTE FUNCTION anonflow_graph_review_event_order();
COMMIT;
