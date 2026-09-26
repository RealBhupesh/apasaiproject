from __future__ import annotations

from sqlalchemy import Connection, text

SECURE_VECTOR_SQL = text("""
SELECT c.id, c.document_version_id, c.section, c.page, c.text, c.classification,
       1 - (e.embedding <=> CAST(:query_embedding AS vector)) AS semantic_score,
       ts_rank_cd(c.search_vector, websearch_to_tsquery('english', :query)) AS keyword_score
FROM documents.embeddings e
JOIN documents.chunks c ON c.id=e.chunk_id AND c.tenant_id=e.tenant_id
JOIN documents.document_versions v ON v.id=c.document_version_id AND v.tenant_id=c.tenant_id
WHERE c.tenant_id=current_setting('app.tenant_id')::uuid
  AND c.jurisdiction=:jurisdiction
  AND v.effective_from<=:as_of
  AND (v.effective_to IS NULL OR :as_of<v.effective_to)
  AND v.transaction_from<=:known_at
  AND (v.transaction_to IS NULL OR :known_at<v.transaction_to)
ORDER BY ((1-(e.embedding <=> CAST(:query_embedding AS vector)))*0.75 + ts_rank_cd(c.search_vector,websearch_to_tsquery('english',:query))*0.25) DESC
LIMIT :limit
""")


def secure_hybrid_query(connection: Connection, **params):
    """RLS plus pre-scoring tenant/temporal predicates; never post-filter protected rows."""
    return connection.execute(SECURE_VECTOR_SQL, params).mappings().all()
