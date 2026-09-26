import pytest
from app.config import RuntimeMode,Settings

def test_demo_is_explicit_default(monkeypatch):
    monkeypatch.delenv("APAS_RUNTIME_MODE",raising=False);assert Settings.from_env().runtime_mode==RuntimeMode.DEMO
def test_production_missing_dependencies_fails_closed(monkeypatch):
    monkeypatch.setenv("APAS_RUNTIME_MODE","production")
    for key in ["DATABASE_URL","AUTH_DATABASE_URL","OIDC_ISSUER","OIDC_AUDIENCE","OIDC_PUBLIC_KEY","EVIDENCE_SIGNING_PRIVATE_KEY"]:monkeypatch.delenv(key,raising=False)
    with pytest.raises(RuntimeError,match="dependencies missing"):Settings.from_env()
def test_invalid_mode_fails_closed(monkeypatch):
    monkeypatch.setenv("APAS_RUNTIME_MODE","auto")
    with pytest.raises(RuntimeError):Settings.from_env()
