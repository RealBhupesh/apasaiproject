from fastapi.testclient import TestClient
from app.api.main import app

client=TestClient(app)

def test_health_and_ask():
    assert client.get('/health').status_code==200
    r=client.post('/ask',json={"question":"When must Alpha facilities report a sample result?","identity":"alpha-analyst","jurisdiction":"FEDERAL","as_of_date":"2026-06-01"})
    assert r.status_code==200 and r.json()["disposition"]=="ANSWER"

def test_unknown_identity_is_non_sensitive_denial():
    r=client.post('/ask',json={"question":"Show me records","identity":"attacker","jurisdiction":"FEDERAL","as_of_date":"2026-06-01"})
    assert r.status_code==403 and r.json()["detail"]=="Request denied by policy"


def test_signed_evidence_package_round_trip():
    answer=client.post('/ask',json={"question":"When must Alpha facilities report a sample result?","identity":"alpha-analyst","jurisdiction":"FEDERAL","as_of_date":"2026-06-01"}).json()
    package=client.get(f"/evidence-packages/{answer['evidence_package_id']}",headers={"x-demo-identity":"alpha-analyst"})
    assert package.status_code==200 and package.json()["signature_valid"] is True

def test_security_decisions_require_privileged_role():
    answer=client.post('/ask',json={"question":"When must Alpha facilities report a sample result?","identity":"alpha-analyst","jurisdiction":"FEDERAL","as_of_date":"2026-06-01"}).json()
    denied=client.get(f"/security/decisions/{answer['request_id']}",headers={"x-demo-identity":"alpha-analyst"})
    assert denied.status_code==403

def test_provenance_existence_denials_are_normalized():
    answer=client.post('/ask',json={"question":"When must Alpha facilities report a sample result?","identity":"alpha-analyst","jurisdiction":"FEDERAL","as_of_date":"2026-06-01"}).json();claim=answer["claims"][0]["id"]
    hidden=client.get(f'/claims/{claim}/provenance',headers={"x-demo-identity":"beta-analyst"});missing=client.get('/claims/00000000-0000-0000-0000-000000000000/provenance',headers={"x-demo-identity":"beta-analyst"})
    assert (hidden.status_code,hidden.json())==(missing.status_code,missing.json())==(404,{"detail":"Resource not found"})

def test_review_and_audit_counts_require_dedicated_roles():
    assert client.get('/reviews',headers={"x-demo-identity":"alpha-viewer"}).status_code==403
    assert client.get('/audit/verify',headers={"x-demo-identity":"alpha-viewer"}).json()=={"detail":"Request denied by policy"}
