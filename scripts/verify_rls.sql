\set ON_ERROR_STOP on
BEGIN;
-- Run as a LOGIN role granted apas_api_reader, never as table owner or superuser.
SELECT set_config('app.tenant_id','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',true);
SELECT set_config('app.user_id','rls-test-alpha',true);
SELECT set_config('app.clearance','PUBLIC',true);
SELECT set_config('app.role','viewer',true);
SELECT set_config('app.jurisdictions','FEDERAL',true);
DO $$
BEGIN
 IF EXISTS (SELECT 1 FROM documents.chunks WHERE tenant_id <> current_setting('app.tenant_id')::uuid) THEN
   RAISE EXCEPTION 'RLS FAILURE: cross-tenant chunk visible';
 END IF;
 IF EXISTS (SELECT 1 FROM documents.embeddings WHERE tenant_id <> current_setting('app.tenant_id')::uuid) THEN
   RAISE EXCEPTION 'RLS FAILURE: cross-tenant vector visible';
 END IF;
 IF EXISTS (SELECT 1 FROM knowledge.relations WHERE tenant_id <> current_setting('app.tenant_id')::uuid) THEN
   RAISE EXCEPTION 'RLS FAILURE: cross-tenant graph row visible';
 END IF;
 IF EXISTS (SELECT 1 FROM documents.chunks WHERE security.classification_rank(classification) > security.classification_rank('PUBLIC')) THEN
   RAISE EXCEPTION 'RLS FAILURE: high-classification chunk visible';
 END IF;
END $$;
ROLLBACK;
