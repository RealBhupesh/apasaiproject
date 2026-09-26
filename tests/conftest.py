from __future__ import annotations

from uuid import uuid4

import pytest

from app.audit.ledger import AuditLedger
from app.auth.demo import authenticate_demo
from app.db.repositories.memory import MemoryStore
from app.db.seed import seed_demo
from app.graph.repository import SecureGraphRepository
from app.orchestration.workflow import DefensibleGraphRAG
from app.security.policies import PolicyEngine


@pytest.fixture
def system():
    store=MemoryStore(); policy=PolicyEngine(store.save_decision); rels=seed_demo(store); ledger=AuditLedger()
    return store, policy, SecureGraphRepository(rels,policy), ledger


@pytest.fixture
def workflow(system):
    store,policy,graph,ledger=system
    return DefensibleGraphRAG(store,policy,graph,ledger)


def context(identity: str):
    return authenticate_demo(identity, uuid4(), "regulatory_search" if "agent" in identity else None)
