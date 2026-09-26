BEGIN;
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE SCHEMA IF NOT EXISTS security;
CREATE SCHEMA IF NOT EXISTS documents;
CREATE SCHEMA IF NOT EXISTS knowledge;
CREATE SCHEMA IF NOT EXISTS provenance;
CREATE SCHEMA IF NOT EXISTS audit;

DO $$ BEGIN
  CREATE TYPE security.classification AS ENUM ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
  CREATE TYPE security.access_decision_value AS ENUM ('ALLOW','DENY','ESCALATE');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ DECLARE r text; BEGIN
  FOREACH r IN ARRAY ARRAY['apas_api_reader','apas_api_writer','apas_graph_reader','apas_ingestion_worker','apas_audit_writer','apas_security_admin'] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=r) THEN EXECUTE format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS',r); END IF;
  END LOOP;
END $$;

CREATE TABLE security.tenants (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text NOT NULL UNIQUE,
 created_at timestamptz NOT NULL DEFAULT now(), created_by text NOT NULL
);
CREATE TABLE security.users (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), external_subject text NOT NULL UNIQUE,
 created_at timestamptz NOT NULL DEFAULT now(), created_by text NOT NULL
);
CREATE TABLE security.memberships (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES security.tenants,
 user_id uuid NOT NULL REFERENCES security.users, status text NOT NULL DEFAULT 'ACTIVE',
 created_at timestamptz NOT NULL DEFAULT now(), created_by text NOT NULL, UNIQUE(tenant_id,user_id)
);
CREATE TABLE security.roles (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES security.tenants,
 name text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), created_by text NOT NULL, UNIQUE(tenant_id,name)
);
CREATE TABLE security.permissions (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), operation text NOT NULL, resource_type text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), created_by text NOT NULL, UNIQUE(operation,resource_type)
);
CREATE TABLE security.role_permissions (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES security.tenants,
 role_id uuid NOT NULL REFERENCES security.roles, permission_id uuid NOT NULL REFERENCES security.permissions,
 created_at timestamptz NOT NULL DEFAULT now(), created_by text NOT NULL, UNIQUE(tenant_id,role_id,permission_id)
);
CREATE TABLE security.user_clearances (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES security.tenants,
 user_id uuid NOT NULL REFERENCES security.users, clearance security.classification NOT NULL,
 jurisdictions text[] NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now(), created_by text NOT NULL,
 UNIQUE(tenant_id,user_id)
);
CREATE TABLE security.policies (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES security.tenants,
 name text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), created_by text NOT NULL
);
CREATE TABLE security.policy_versions (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES security.tenants,
 policy_id uuid NOT NULL REFERENCES security.policies, version text NOT NULL, definition jsonb NOT NULL,
 active_from timestamptz NOT NULL, active_to timestamptz,
 created_at timestamptz NOT NULL DEFAULT now(), created_by text NOT NULL, UNIQUE(policy_id,version)
);
CREATE TABLE security.access_decisions (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), request_id uuid NOT NULL, tenant_id uuid NOT NULL REFERENCES security.tenants,
 actor_type text NOT NULL, actor_id text NOT NULL, resource_type text NOT NULL, resource_id text NOT NULL,
 operation text NOT NULL, decision security.access_decision_value NOT NULL, reason text NOT NULL,
 policy_id uuid, policy_version text NOT NULL, metadata jsonb NOT NULL DEFAULT '{}',
 timestamp timestamptz NOT NULL DEFAULT now(), created_at timestamptz NOT NULL DEFAULT now(), created_by text NOT NULL
);

CREATE TABLE documents.source_documents (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES security.tenants,
 authority text NOT NULL, jurisdiction text NOT NULL, classification security.classification NOT NULL,
 owner_id uuid, original_filename text NOT NULL, storage_uri text NOT NULL, sha256 char(64) NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), created_by text NOT NULL
);
CREATE TABLE documents.document_versions (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES security.tenants,
 source_document_id uuid NOT NULL REFERENCES documents.source_documents, version text NOT NULL, sha256 char(64) NOT NULL,
 effective_from date NOT NULL, effective_to date, transaction_from timestamptz NOT NULL DEFAULT now(),
 transaction_to timestamptz, parser_version text NOT NULL, ingested_at timestamptz NOT NULL DEFAULT now(),
 created_at timestamptz NOT NULL DEFAULT now(), created_by text NOT NULL,
 CHECK(effective_to IS NULL OR effective_to > effective_from),
 CHECK(transaction_to IS NULL OR transaction_to > transaction_from), UNIQUE(source_document_id,version,transaction_from)
);
CREATE TABLE documents.chunks (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES security.tenants,
 document_version_id uuid NOT NULL REFERENCES documents.document_versions, section text, page integer,
 text text NOT NULL, classification security.classification NOT NULL, jurisdiction text NOT NULL, owner_id uuid,
 content_hash char(64) NOT NULL, search_vector tsvector GENERATED ALWAYS AS (to_tsvector('english',text)) STORED,
 created_at timestamptz NOT NULL DEFAULT now(), created_by text NOT NULL
);
CREATE TABLE documents.embeddings (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES security.tenants,
 chunk_id uuid NOT NULL REFERENCES documents.chunks ON DELETE RESTRICT, embedding vector(1536) NOT NULL,
 embedding_model text NOT NULL, embedding_model_version text NOT NULL,
 classification security.classification NOT NULL, jurisdiction text NOT NULL, owner_id uuid,
 created_at timestamptz NOT NULL DEFAULT now(), created_by text NOT NULL, UNIQUE(chunk_id,embedding_model,embedding_model_version)
);
CREATE INDEX chunks_search_idx ON documents.chunks USING gin(search_vector);
CREATE INDEX embeddings_hnsw_idx ON documents.embeddings USING hnsw (embedding vector_cosine_ops);
CREATE INDEX chunks_security_idx ON documents.chunks(tenant_id,classification,jurisdiction);

CREATE TABLE knowledge.relations (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES security.tenants,
 named_graph text NOT NULL, subject text NOT NULL, predicate text NOT NULL, object text NOT NULL,
 source_chunk_id uuid NOT NULL REFERENCES documents.chunks, classification security.classification NOT NULL,
 jurisdiction text NOT NULL, owner_id uuid, valid_from date NOT NULL, valid_to date,
 transaction_from timestamptz NOT NULL DEFAULT now(), transaction_to timestamptz,
 created_at timestamptz NOT NULL DEFAULT now(), created_by text NOT NULL
);
CREATE TABLE provenance.claims (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES security.tenants,
 request_id uuid NOT NULL, text text NOT NULL, status text NOT NULL, classification security.classification NOT NULL,
 jurisdiction text NOT NULL, owner_id uuid, lineage jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), created_by text NOT NULL
);
CREATE TABLE audit.events (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES security.tenants,
 timestamp timestamptz NOT NULL DEFAULT now(), actor text NOT NULL, event_type text NOT NULL,
 resource text NOT NULL, request_id uuid NOT NULL, metadata jsonb NOT NULL DEFAULT '{}', previous_hash char(64) NOT NULL,
 event_hash char(64) NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), created_by text NOT NULL
);

CREATE OR REPLACE FUNCTION security.classification_rank(c security.classification) RETURNS integer
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$ SELECT CASE c WHEN 'PUBLIC' THEN 0 WHEN 'INTERNAL' THEN 1 WHEN 'CONFIDENTIAL' THEN 2 WHEN 'RESTRICTED' THEN 3 END $$;
CREATE OR REPLACE FUNCTION security.current_tenant() RETURNS uuid LANGUAGE sql STABLE AS $$ SELECT nullif(current_setting('app.tenant_id',true),'')::uuid $$;
CREATE OR REPLACE FUNCTION security.current_clearance() RETURNS security.classification LANGUAGE sql STABLE AS $$ SELECT coalesce(nullif(current_setting('app.clearance',true),'')::security.classification,'PUBLIC') $$;
CREATE OR REPLACE FUNCTION security.allowed_jurisdiction(j text) RETURNS boolean LANGUAGE sql STABLE AS $$ SELECT j = ANY(string_to_array(coalesce(current_setting('app.jurisdictions',true),''),',')) $$;
CREATE OR REPLACE FUNCTION security.can_read(t uuid,c security.classification,j text) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT t=security.current_tenant() AND security.classification_rank(c)<=security.classification_rank(security.current_clearance()) AND security.allowed_jurisdiction(j)
$$;

DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['security.memberships','security.roles','security.role_permissions','security.user_clearances','security.policies','security.policy_versions','security.access_decisions','documents.source_documents','documents.document_versions','documents.chunks','documents.embeddings','knowledge.relations','provenance.claims','audit.events'] LOOP
  EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY',t); EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY',t);
 END LOOP;
END $$;

CREATE POLICY tenant_memberships ON security.memberships USING (tenant_id=security.current_tenant());
CREATE POLICY tenant_roles ON security.roles USING (tenant_id=security.current_tenant());
CREATE POLICY tenant_role_permissions ON security.role_permissions USING (tenant_id=security.current_tenant());
CREATE POLICY tenant_clearances ON security.user_clearances USING (tenant_id=security.current_tenant());
CREATE POLICY tenant_policies ON security.policies USING (tenant_id=security.current_tenant());
CREATE POLICY tenant_policy_versions ON security.policy_versions USING (tenant_id=security.current_tenant());
CREATE POLICY tenant_decisions ON security.access_decisions USING (tenant_id=security.current_tenant());
CREATE POLICY secured_documents ON documents.source_documents USING (security.can_read(tenant_id,classification,jurisdiction));
CREATE POLICY tenant_versions ON documents.document_versions USING (tenant_id=security.current_tenant());
CREATE POLICY secured_chunks ON documents.chunks USING (security.can_read(tenant_id,classification,jurisdiction));
CREATE POLICY secured_embeddings ON documents.embeddings USING (security.can_read(tenant_id,classification,jurisdiction));
CREATE POLICY secured_graph ON knowledge.relations USING (security.can_read(tenant_id,classification,jurisdiction));
CREATE POLICY secured_claims ON provenance.claims USING (security.can_read(tenant_id,classification,jurisdiction));
CREATE POLICY tenant_audit ON audit.events USING (tenant_id=security.current_tenant());

CREATE OR REPLACE FUNCTION audit.reject_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit events are append-only'; END $$;
CREATE TRIGGER audit_no_update_delete BEFORE UPDATE OR DELETE ON audit.events FOR EACH ROW EXECUTE FUNCTION audit.reject_mutation();

REVOKE ALL ON SCHEMA security,documents,knowledge,provenance,audit FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA security,documents,knowledge,provenance,audit FROM PUBLIC;
GRANT USAGE ON SCHEMA security,documents,knowledge,provenance TO apas_api_reader;
GRANT SELECT ON documents.source_documents,documents.document_versions,documents.chunks,documents.embeddings,knowledge.relations,provenance.claims TO apas_api_reader;
GRANT apas_api_reader TO apas_graph_reader;
GRANT SELECT,INSERT,UPDATE ON documents.source_documents,documents.document_versions,documents.chunks,documents.embeddings,knowledge.relations TO apas_ingestion_worker;
GRANT USAGE ON SCHEMA documents,knowledge TO apas_ingestion_worker;
GRANT USAGE ON SCHEMA audit TO apas_audit_writer;
GRANT INSERT,SELECT ON audit.events TO apas_audit_writer;
GRANT USAGE ON SCHEMA security TO apas_security_admin;
GRANT SELECT,INSERT,UPDATE ON ALL TABLES IN SCHEMA security TO apas_security_admin;
-- Migration owner is intentionally not granted to runtime identities. Provision LOGIN roles separately and grant only these group roles.
COMMIT;
