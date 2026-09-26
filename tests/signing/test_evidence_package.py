from dataclasses import replace
from uuid import uuid4
from app.signing.evidence_package import Ed25519SigningKey,EvidencePackageService


def test_signed_evidence_package_detects_tampering():
    svc=EvidencePackageService(Ed25519SigningKey())
    p=svc.issue(tenant_id=uuid4(),request_id=uuid4(),answer_classification="INTERNAL",jurisdiction="FEDERAL",question="q",answer="a",claims=[{"x":1}],evidence=[{"y":2}],document_versions=[{"z":3}],policy_versions=["1"],model_manifest={"m":"1"},temporal_parameters={"as_of":"2027-01-01"},audit_checkpoint="abc")
    assert svc.verify(p)
    assert not svc.verify(replace(p,answer_hash="0"*64))
