from __future__ import annotations
from datetime import date,datetime,timezone
from uuid import UUID,uuid4
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import Engine,create_engine
from app.auth.postgres import DatabaseMembershipAuthority
from app.config import Settings
from app.db.repositories.postgres_runtime import PostgresAuditRepository,PostgresDocumentRepository,PostgresEvidencePackageRepository,PostgresGraphRepository,PostgresProvenanceRepository,PostgresReviewRepository,PostgresSecurityDecisionRepository
from app.db.rls.context import set_local_security_context
from app.orchestration.production import ProductionDefensibleGraphRAG
from app.security.capability_tokens import CapabilityTokenService,PostgresCapabilityState
from app.security.identity import OIDCAuthenticator
from app.signing.evidence_package import Ed25519SigningKey,EvidencePackageService
class ProductionRuntime:
    def __init__(self,settings:Settings):
        self.settings=settings;self.engine:Engine=create_engine(settings.database_url,pool_pre_ping=True);self.auth_engine:Engine=create_engine(settings.auth_database_url,pool_pre_ping=True)
        self.auth=OIDCAuthenticator(issuer=settings.oidc_issuer,audience=settings.oidc_audience,public_key=settings.oidc_public_key.replace("\\n","\n"),memberships=DatabaseMembershipAuthority(self.auth_engine))
        raw=settings.evidence_signing_private_key.replace("\\n","\n").encode();private=serialization.load_pem_private_key(raw,password=None)
        if not isinstance(private,Ed25519PrivateKey):raise RuntimeError("production signing key must be Ed25519")
        self.key=Ed25519SigningKey(private,"production-ed25519-v1")
    def ask(self,*,bearer_token:str,question:str,jurisdiction:str,as_of:date,known_at:datetime|None,purpose:str,selected_tenant:UUID|None,capability_token:str|None=None):
        request_id=uuid4();context=self.auth.authenticate(bearer_token,request_id,purpose,selected_tenant);denied=False;result=None
        with self.engine.begin() as connection:
            set_local_security_context(connection,context);audit=PostgresAuditRepository(connection);audit.append(context,"AUTHENTICATION_SUCCEEDED",str(request_id),{"issuer":context.identity_issuer})
            if jurisdiction not in context.jurisdictions:
                audit.append(context,"AUTHORIZATION_DENY",str(request_id),{"reason":"jurisdiction denied"});denied=True
            else:
                audit.append(context,"AUTHORIZATION_ALLOW",str(request_id),{"operation":"ASK","jurisdiction":jurisdiction})
            if not denied and context.actor_type=="agent":
                try:
                    if not capability_token:raise PermissionError("capability denied")
                    CapabilityTokenService(self.key,PostgresCapabilityState(connection,audience=self.settings.oidc_audience,tool="regulatory_search",operation="READ",jurisdiction=jurisdiction,purpose=purpose,requested_classification=int(context.clearance))).verify(capability_token,subject=context.actor_id,tenant_id=context.tenant_id,audience=self.settings.oidc_audience,tool="regulatory_search",operation="READ",jurisdiction=jurisdiction,purpose=purpose,requested_classification=int(context.clearance));audit.append(context,"CAPABILITY_USED",context.actor_id,{"tool":"regulatory_search"})
                except PermissionError:
                    audit.append(context,"CAPABILITY_DENIED",context.actor_id,{"tool":"regulatory_search"});denied=True
            if not denied:
                workflow=ProductionDefensibleGraphRAG(PostgresDocumentRepository(connection),PostgresGraphRepository(connection),PostgresProvenanceRepository(connection),audit,PostgresSecurityDecisionRepository(connection),PostgresEvidencePackageRepository(connection),PostgresReviewRepository(connection),EvidencePackageService(self.key));result=workflow.ask(question,context,jurisdiction,as_of,known_at or datetime.now(timezone.utc))
        if denied:raise PermissionError("request denied")
        return result
