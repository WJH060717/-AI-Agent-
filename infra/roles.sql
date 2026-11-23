-- Run once as migration owner, AFTER migrate. Set login passwords interactively with psql \password.
-- NOLOGIN until operator sets a password and explicitly enables LOGIN.
CREATE ROLE trace_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE;
CREATE ROLE trace_reader NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE;
GRANT USAGE ON SCHEMA public TO trace_app, trace_reader;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO trace_app;
REVOKE INSERT, UPDATE, DELETE ON alembic_version FROM trace_app;
REVOKE UPDATE, DELETE ON audit_logs, raw_objects, events FROM trace_app;
REVOKE UPDATE, DELETE ON findings, snapshots, reports, batch_events FROM trace_app;
REVOKE UPDATE, DELETE ON dataset_contexts, workspace_private_keys FROM trace_app;
REVOKE UPDATE, DELETE ON incidents, incident_details, incident_catalogs FROM trace_app;
REVOKE UPDATE, DELETE ON agent_transitions FROM trace_app;
REVOKE UPDATE, DELETE ON report_reviews FROM trace_app;
GRANT USAGE, SELECT ON SEQUENCE report_reviews_seq_seq TO trace_app;
GRANT SELECT ON events, datasets, analysis_sessions, session_events, raw_objects TO trace_reader;
-- Do not give the app or reader schema CREATE privileges. Future migrations must update grants.
