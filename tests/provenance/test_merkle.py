import hashlib
from app.audit.advanced import create_checkpoint,merkle_root
from app.signing.evidence_package import Ed25519SigningKey

def test_merkle_checkpoint_is_signed():
    hashes=[hashlib.sha256(x).hexdigest() for x in [b"a",b"b",b"c"]]
    key=Ed25519SigningKey(); cp=create_checkpoint("tenant",hashes,key)
    payload=f"tenant|3|{cp.merkle_root}|{cp.chain_head}|{cp.created_at.isoformat()}".encode()
    key.verify(payload,bytes.fromhex(cp.signature_hex)); assert cp.merkle_root==merkle_root(hashes)
