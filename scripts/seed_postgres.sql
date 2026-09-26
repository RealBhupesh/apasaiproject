\set ON_ERROR_STOP on
INSERT INTO security.tenants(id,name,created_by) VALUES
 ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','Tenant Alpha','ci'),
 ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','Tenant Beta','ci') ON CONFLICT DO NOTHING;
INSERT INTO documents.source_documents(id,tenant_id,authority,jurisdiction,classification,original_filename,storage_uri,sha256,created_by) VALUES
 ('a0000000-0000-0000-0000-000000000001','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','Synthetic','FEDERAL','PUBLIC','alpha.txt','demo://alpha',repeat('a',64),'ci'),
 ('a0000000-0000-0000-0000-000000000002','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','Synthetic','FEDERAL','RESTRICTED','alpha-secret.txt','demo://alpha-secret',repeat('b',64),'ci'),
 ('b0000000-0000-0000-0000-000000000001','bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','Synthetic','FEDERAL','PUBLIC','beta.txt','demo://beta',repeat('c',64),'ci');
INSERT INTO documents.document_versions(id,tenant_id,source_document_id,version,sha256,effective_from,parser_version,created_by) VALUES
 ('a1000000-0000-0000-0000-000000000001','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','a0000000-0000-0000-0000-000000000001','1',repeat('a',64),'2026-01-01','ci','ci'),
 ('a1000000-0000-0000-0000-000000000002','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','a0000000-0000-0000-0000-000000000002','1',repeat('b',64),'2026-01-01','ci','ci'),
 ('b1000000-0000-0000-0000-000000000001','bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','b0000000-0000-0000-0000-000000000001','1',repeat('c',64),'2026-01-01','ci','ci');
INSERT INTO documents.chunks(id,tenant_id,document_version_id,section,page,text,classification,jurisdiction,content_hash,created_by) VALUES
 ('a2000000-0000-0000-0000-000000000001','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','a1000000-0000-0000-0000-000000000001','s',1,'SYNTHETIC Alpha public','PUBLIC','FEDERAL',repeat('a',64),'ci'),
 ('a2000000-0000-0000-0000-000000000002','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','a1000000-0000-0000-0000-000000000002','s',1,'SYNTHETIC Alpha restricted','RESTRICTED','FEDERAL',repeat('b',64),'ci'),
 ('b2000000-0000-0000-0000-000000000001','bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','b1000000-0000-0000-0000-000000000001','s',1,'SYNTHETIC Beta public','PUBLIC','FEDERAL',repeat('c',64),'ci');
INSERT INTO documents.embeddings(tenant_id,chunk_id,embedding,embedding_model,embedding_model_version,classification,jurisdiction,created_by) VALUES
 ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','a2000000-0000-0000-0000-000000000001',array_fill(0::real,ARRAY[1536])::vector,'ci','1','PUBLIC','FEDERAL','ci'),
 ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','b2000000-0000-0000-0000-000000000001',array_fill(0::real,ARRAY[1536])::vector,'ci','1','PUBLIC','FEDERAL','ci');
INSERT INTO knowledge.relations(tenant_id,named_graph,subject,predicate,object,source_chunk_id,classification,jurisdiction,valid_from,created_by) VALUES
 ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','tenant:alpha:public','urn:alpha','issuedBy','urn:synthetic','a2000000-0000-0000-0000-000000000001','PUBLIC','FEDERAL','2026-01-01','ci'),
 ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','tenant:beta:public','urn:beta','issuedBy','urn:synthetic','b2000000-0000-0000-0000-000000000001','PUBLIC','FEDERAL','2026-01-01','ci');
INSERT INTO provenance.claims(tenant_id,request_id,text,status,classification,jurisdiction,lineage,created_by) VALUES
 ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',gen_random_uuid(),'alpha claim','SUPPORTED','PUBLIC','FEDERAL','{}','ci'),
 ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',gen_random_uuid(),'beta claim','SUPPORTED','PUBLIC','FEDERAL','{}','ci');
