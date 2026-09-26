from __future__ import annotations
import hashlib,mimetypes,re
from dataclasses import dataclass,field
from enum import StrEnum
from typing import Protocol
from uuid import UUID,uuid4
from app.llm.boundary import INJECTION_PATTERNS
from app.security.context import Classification
class IngestionStatus(StrEnum):ACCEPTED="ACCEPTED";QUARANTINED="QUARANTINED";PENDING_REVIEW="PENDING_REVIEW"
@dataclass(frozen=True)
class Upload:
    tenant_id:UUID;filename:str;content:bytes;declared_mime:str;classification:Classification;jurisdiction:str;authority:str
@dataclass
class IngestionManifest:
    ingestion_id:UUID;sha256:str;detected_mime:str;parser_version:str;chunker_version:str;embedding_model:str;status:IngestionStatus;findings:list[str]=field(default_factory=list)
class MalwareScanner(Protocol):
    def scan(self,content:bytes)->bool:...
class ContentTypeDetector(Protocol):
    def detect(self,content:bytes)->str:...
class SignatureContentTypeDetector:
    """Content-aware, non-executing detector for the intentionally narrow allow-list."""
    def detect(self,content:bytes)->str:
        if content.startswith(b"%PDF-"):return "application/pdf"
        if content.startswith((b"PK\x03\x04",b"MZ",b"\x7fELF")):return "application/octet-stream"
        sample=content[:8192]
        if b"\x00" in sample:return "application/octet-stream"
        try:sample.decode("utf-8")
        except UnicodeDecodeError:return "application/octet-stream"
        return "text/plain"
class SafeDemoScanner:
    def scan(self,content:bytes)->bool:return b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE" not in content
class SecureIngestionPipeline:
    ALLOWED_MIME=frozenset({"text/plain","application/pdf","text/markdown"})
    def __init__(self,scanner:MalwareScanner,detector:ContentTypeDetector|None=None):self.scanner=scanner;self.detector=detector or SignatureContentTypeDetector()
    def inspect(self,upload:Upload)->IngestionManifest:
        findings=[];detected=self.detector.detect(upload.content);extension=mimetypes.guess_type(upload.filename)[0] or "application/octet-stream"
        compatible_text={detected,upload.declared_mime,extension}<={"text/plain","text/markdown"}
        if not compatible_text and len({detected,upload.declared_mime,extension})>1:findings.append("mime mismatch")
        if detected not in self.ALLOWED_MIME:findings.append("unsupported mime")
        if not self.scanner.scan(upload.content):findings.append("malware signature")
        text=upload.content[:2_000_000].decode("utf-8",errors="ignore")
        if INJECTION_PATTERNS.search(text):findings.append("prompt injection language")
        if re.search(r"(?:api[_-]?key|password|secret)\s*[:=]\s*\S+",text,re.I):findings.append("possible secret")
        hard={"mime mismatch","unsupported mime","malware signature","possible secret"}&set(findings)
        status=IngestionStatus.QUARANTINED if hard else (IngestionStatus.PENDING_REVIEW if findings or upload.classification>=Classification.CONFIDENTIAL else IngestionStatus.ACCEPTED)
        return IngestionManifest(uuid4(),hashlib.sha256(upload.content).hexdigest(),detected,"sandbox-parser-v1","semantic-chunker-v1","embedding-model-pinned-v1",status,findings)
