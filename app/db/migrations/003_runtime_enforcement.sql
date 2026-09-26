BEGIN;
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='apas_auth_reader') THEN
  CREATE ROLE apas_auth_reader NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
 END IF;
END $$;

CREATE OR REPLACE FUNCTION security.resolve_identity_memberships(p_issuer text,p_subject text)
RETURNS TABLE(issuer text,subject text,tenant_id uuid,roles text[],clearance text,jurisdictions text[],active boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=security,pg_catalog AS $$
 SELECT i.issuer,i.subject,i.tenant_id,array_agg(DISTINCT r.name),uc.clearance::text,uc.jurisdictions,i.active
 FROM security.identities i
 JOIN security.memberships m ON m.user_id=i.user_id AND m.tenant_id=i.tenant_id AND m.status='ACTIVE'
 JOIN security.user_clearances uc ON uc.user_id=i.user_id AND uc.tenant_id=i.tenant_id
 JOIN security.membership_roles mr ON mr.membership_id=m.id AND mr.tenant_id=m.tenant_id
 JOIN security.roles r ON r.id=mr.role_id AND r.tenant_id=mr.tenant_id
 WHERE i.issuer=p_issuer AND i.subject=p_subject AND i.active=true
 GROUP BY i.issuer,i.subject,i.tenant_id,uc.clearance,uc.jurisdictions,i.active
$$;
REVOKE ALL ON FUNCTION security.resolve_identity_memberships(text,text) FROM PUBLIC;
GRANT USAGE ON SCHEMA security TO apas_auth_reader;
GRANT EXECUTE ON FUNCTION security.resolve_identity_memberships(text,text) TO apas_auth_reader;

ALTER TABLE audit.events ADD COLUMN IF NOT EXISTS sequence bigint;
ALTER TABLE audit.events ADD COLUMN IF NOT EXISTS event_payload jsonb;
CREATE UNIQUE INDEX IF NOT EXISTS audit_events_tenant_sequence ON audit.events(tenant_id,sequence);
DROP FUNCTION audit.append_event(uuid,text,text,text,uuid,jsonb,text);
CREATE FUNCTION audit.append_event(p_tenant uuid,p_actor text,p_event_type text,p_resource text,p_request uuid,p_metadata jsonb,p_created_by text)
RETURNS audit.events LANGUAGE plpgsql SECURITY DEFINER SET search_path=audit,pg_catalog AS $$
DECLARE h audit.chain_heads;e audit.events;payload jsonb;next_hash text;
BEGIN
 IF p_tenant<>security.current_tenant() THEN RAISE EXCEPTION 'tenant mismatch'; END IF;
 INSERT INTO audit.chain_heads(tenant_id,created_by) VALUES(p_tenant,p_created_by) ON CONFLICT DO NOTHING;
 SELECT * INTO h FROM audit.chain_heads WHERE tenant_id=p_tenant FOR UPDATE;
 payload=jsonb_build_object('tenant_id',p_tenant,'actor',p_actor,'event_type',p_event_type,'resource',p_resource,'request_id',p_request,'metadata',p_metadata,'sequence',h.sequence+1);
 next_hash=encode(public.digest(payload::text||h.event_hash,'sha256'),'hex');
 INSERT INTO audit.events(tenant_id,actor,event_type,resource,request_id,metadata,previous_hash,event_hash,created_by,sequence,event_payload)
 VALUES(p_tenant,p_actor,p_event_type,p_resource,p_request,p_metadata,h.event_hash,next_hash,p_created_by,h.sequence+1,payload) RETURNING * INTO e;
 UPDATE audit.chain_heads SET sequence=h.sequence+1,event_hash=next_hash,updated_at=now() WHERE tenant_id=p_tenant;
 RETURN e;
END $$;
REVOKE ALL ON FUNCTION audit.append_event(uuid,text,text,text,uuid,jsonb,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit.append_event(uuid,text,text,text,uuid,jsonb,text) TO apas_api_writer,apas_audit_writer;

GRANT USAGE ON SCHEMA security,provenance,audit TO apas_api_writer;
GRANT INSERT ON security.access_decisions TO apas_api_writer;
GRANT INSERT,SELECT ON provenance.claims,provenance.answer_packages,provenance.model_execution_manifests TO apas_api_writer;
GRANT SELECT,INSERT,UPDATE ON security.human_review_cases,security.human_review_decisions TO apas_api_writer;
CREATE OR REPLACE FUNCTION security.consume_capability(p_nonce text,p_tenant uuid,p_subject text,p_audience text,p_tool text,p_operation text,p_jurisdiction text,p_purpose text,p_requested_classification security.classification)
RETURNS boolean LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=security,pg_catalog AS $$
 WITH spent AS (
  UPDATE security.capability_tokens SET calls_used=calls_used+1
  WHERE nonce=p_nonce AND tenant_id=p_tenant AND subject=p_subject AND audience=p_audience
    AND jurisdiction=p_jurisdiction AND security.classification_rank(classification)>=security.classification_rank(p_requested_classification)
    AND scope->'tools' ? p_tool AND scope->'operations' ? p_operation AND scope->>'purpose'=p_purpose
    AND revoked_at IS NULL AND expires_at>now() AND calls_used<max_calls RETURNING 1
 ) SELECT EXISTS(SELECT 1 FROM spent)
$$;
REVOKE ALL ON FUNCTION security.consume_capability(text,uuid,text,text,text,text,text,text,security.classification) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION security.consume_capability(text,uuid,text,text,text,text,text,text,security.classification) TO apas_api_writer;
GRANT SELECT ON security.capability_tokens TO apas_api_writer;
GRANT SELECT ON audit.events,audit.chain_heads TO apas_api_reader;

ALTER TABLE security.human_review_decisions ADD COLUMN IF NOT EXISTS reviewer_subject text;
ALTER TABLE security.human_review_decisions ADD COLUMN IF NOT EXISTS reviewer_issuer text;
COMMIT;
