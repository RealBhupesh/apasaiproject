BEGIN;

CREATE TABLE security.identities (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES security.tenants,
 issuer text NOT NULL, subject text NOT NULL, user_id uuid NOT NULL REFERENCES security.users,
 active boolean NOT NULL DEFAULT true, created_at timestamptz NOT NULL DEFAULT now(), created_by text NOT NULL,
 UNIQUE(issuer,subject,tenant_id)
);
CREATE TABLE security.capability_tokens (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES security.tenants,
 subject text NOT NULL, audience text NOT NULL, scope jsonb NOT NULL, nonce text NOT NULL UNIQUE,
 expires_at timestamptz NOT NULL, revoked_at timestamptz, max_calls integer NOT NULL CHECK(max_calls>0), calls_used integer NOT NULL DEFAULT 0,
 classification security.classification NOT NULL, jurisdiction text NOT NULL, owner_id uuid,
 created_at timestamptz NOT NULL DEFAULT now(), created_by text NOT NULL
);
CREATE TABLE security.membership_roles (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES security.tenants,
 membership_id uuid NOT NULL REFERENCES security.memberships, role_id uuid NOT NULL REFERENCES security.roles,
 created_at timestamptz NOT NULL DEFAULT now(), created_by text NOT NULL, UNIQUE(tenant_id,membership_id,role_id)
);
CREATE TABLE security.policy_bundle_approvals (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES security.tenants,
 policy_version_id uuid NOT NULL REFERENCES security.policy_versions, approver_id uuid NOT NULL REFERENCES security.users,
 decision text NOT NULL CHECK(decision IN ('APPROVE','REJECT')), rationale text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), created_by text NOT NULL,
 UNIQUE(policy_version_id,approver_id)
);
CREATE TABLE documents.ingestion_manifests (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES security.tenants,
 source_document_id uuid REFERENCES documents.source_documents, sha256 char(64) NOT NULL,
 detected_mime text NOT NULL, malware_scan jsonb NOT NULL, parser_version text NOT NULL,
 chunker_version text NOT NULL, embedding_model text NOT NULL, findings jsonb NOT NULL DEFAULT '[]',
 status text NOT NULL CHECK(status IN ('ACCEPTED','QUARANTINED','PENDING_REVIEW')),
 classification security.classification NOT NULL, jurisdiction text NOT NULL, owner_id uuid,
 created_at timestamptz NOT NULL DEFAULT now(), created_by text NOT NULL
);
CREATE TABLE provenance.answer_packages (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES security.tenants,
 request_id uuid NOT NULL, package jsonb NOT NULL, package_hash char(64) NOT NULL,
 signature text NOT NULL, signing_key_id text NOT NULL, classification security.classification NOT NULL,
 jurisdiction text NOT NULL, owner_id uuid, created_at timestamptz NOT NULL DEFAULT now(), created_by text NOT NULL
);
CREATE TABLE provenance.model_execution_manifests (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES security.tenants,
 request_id uuid NOT NULL, manifest jsonb NOT NULL, manifest_hash char(64) NOT NULL,
 classification security.classification NOT NULL, jurisdiction text NOT NULL, owner_id uuid,
 created_at timestamptz NOT NULL DEFAULT now(), created_by text NOT NULL
);
CREATE TABLE security.human_review_cases (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES security.tenants,
 request_id uuid NOT NULL, status text NOT NULL CHECK(status IN ('OPEN','APPROVED','REJECTED')),
 reason text NOT NULL, conflict jsonb NOT NULL, evidence_ids uuid[] NOT NULL,
 classification security.classification NOT NULL, jurisdiction text NOT NULL, owner_id uuid,
 requested_by text NOT NULL, final_rationale text, decided_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now(), created_by text NOT NULL
);
CREATE TABLE security.human_review_decisions (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES security.tenants,
 case_id uuid NOT NULL REFERENCES security.human_review_cases, reviewer_id uuid NOT NULL REFERENCES security.users,
 decision text NOT NULL CHECK(decision IN ('APPROVE','REJECT')), rationale text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), created_by text NOT NULL, UNIQUE(case_id,reviewer_id)
);
CREATE TABLE audit.chain_heads (
 tenant_id uuid PRIMARY KEY REFERENCES security.tenants, sequence bigint NOT NULL DEFAULT 0,
 event_hash char(64) NOT NULL DEFAULT repeat('0',64), created_at timestamptz NOT NULL DEFAULT now(), created_by text NOT NULL,
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE audit.checkpoints (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES security.tenants,
 sequence bigint NOT NULL, merkle_root char(64) NOT NULL, chain_head char(64) NOT NULL,
 signature text NOT NULL, signing_key_id text NOT NULL, external_anchor_uri text,
 created_at timestamptz NOT NULL DEFAULT now(), created_by text NOT NULL, UNIQUE(tenant_id,sequence)
);

CREATE OR REPLACE FUNCTION audit.append_event(
 p_tenant uuid,p_actor text,p_event_type text,p_resource text,p_request uuid,p_metadata jsonb,p_created_by text
) RETURNS audit.events LANGUAGE plpgsql SECURITY DEFINER SET search_path=audit,pg_catalog AS $$
DECLARE h audit.chain_heads; e audit.events; payload text; next_hash text;
BEGIN
 IF p_tenant <> security.current_tenant() THEN RAISE EXCEPTION 'tenant mismatch'; END IF;
 INSERT INTO audit.chain_heads(tenant_id,created_by) VALUES(p_tenant,p_created_by) ON CONFLICT DO NOTHING;
 SELECT * INTO h FROM audit.chain_heads WHERE tenant_id=p_tenant FOR UPDATE;
 payload=jsonb_build_object('tenant_id',p_tenant,'actor',p_actor,'event_type',p_event_type,'resource',p_resource,'request_id',p_request,'metadata',p_metadata,'sequence',h.sequence+1)::text;
 next_hash=encode(public.digest(payload||h.event_hash,'sha256'),'hex');
 INSERT INTO audit.events(tenant_id,actor,event_type,resource,request_id,metadata,previous_hash,event_hash,created_by)
 VALUES(p_tenant,p_actor,p_event_type,p_resource,p_request,p_metadata,h.event_hash,next_hash,p_created_by) RETURNING * INTO e;
 UPDATE audit.chain_heads SET sequence=h.sequence+1,event_hash=next_hash,updated_at=now() WHERE tenant_id=p_tenant;
 RETURN e;
END $$;
REVOKE ALL ON FUNCTION audit.append_event(uuid,text,text,text,uuid,jsonb,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit.append_event(uuid,text,text,text,uuid,jsonb,text) TO apas_audit_writer;
REVOKE INSERT ON audit.events FROM apas_audit_writer;

DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['security.identities','security.capability_tokens','security.membership_roles','security.policy_bundle_approvals','documents.ingestion_manifests','provenance.answer_packages','provenance.model_execution_manifests','security.human_review_cases','security.human_review_decisions','audit.chain_heads','audit.checkpoints'] LOOP
  EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY',t); EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY tenant_isolation ON %s USING (tenant_id=security.current_tenant()) WITH CHECK (tenant_id=security.current_tenant())',t);
 END LOOP;
END $$;

DROP POLICY tenant_versions ON documents.document_versions;
CREATE POLICY secured_versions ON documents.document_versions USING (
 tenant_id=security.current_tenant() AND EXISTS (
  SELECT 1 FROM documents.source_documents d
  WHERE d.id=source_document_id AND security.can_read(d.tenant_id,d.classification,d.jurisdiction)
 )
);
CREATE POLICY secured_ingestion ON documents.ingestion_manifests AS RESTRICTIVE USING(security.can_read(tenant_id,classification,jurisdiction));
CREATE POLICY secured_packages ON provenance.answer_packages AS RESTRICTIVE USING(security.can_read(tenant_id,classification,jurisdiction));
CREATE POLICY secured_manifests ON provenance.model_execution_manifests AS RESTRICTIVE USING(security.can_read(tenant_id,classification,jurisdiction));
CREATE POLICY secured_reviews ON security.human_review_cases AS RESTRICTIVE USING(security.can_read(tenant_id,classification,jurisdiction));

GRANT SELECT ON documents.ingestion_manifests,provenance.answer_packages,provenance.model_execution_manifests TO apas_api_reader;
GRANT SELECT,INSERT,UPDATE ON documents.ingestion_manifests TO apas_ingestion_worker;
GRANT SELECT ON audit.chain_heads,audit.checkpoints TO apas_audit_writer;
GRANT INSERT ON audit.checkpoints TO apas_audit_writer;
GRANT SELECT,INSERT,UPDATE ON security.human_review_cases,security.human_review_decisions TO apas_security_admin;
GRANT SELECT,INSERT,UPDATE ON security.capability_tokens,security.membership_roles,security.policy_bundle_approvals TO apas_security_admin;

COMMIT;
