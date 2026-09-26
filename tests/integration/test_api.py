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
