from pathlib import Path

SQL=Path("app/db/migrations/001_v3.sql").read_text()

def test_rls_and_non_bypass_contract():
    assert "FORCE ROW LEVEL SECURITY" in SQL
    assert "NOBYPASSRLS" in SQL and "NOSUPERUSER" in SQL
    assert "security.can_read" in SQL
    assert "CREATE POLICY secured_embeddings" in SQL

def test_audit_is_append_only_at_database_layer():
    assert "audit_no_update_delete" in SQL
