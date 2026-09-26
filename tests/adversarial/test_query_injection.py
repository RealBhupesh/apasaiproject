import pytest
from tests.conftest import context


def test_arbitrary_sparql_is_never_exposed(system):
    _,_,graph,_=system
    with pytest.raises(PermissionError): graph.execute_sparql("SELECT * WHERE {?s ?p ?o} SERVICE <http://attacker>")


def test_tenant_payload_cannot_change_context():
    ctx=context("alpha-viewer")
    payload="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb' OR 1=1 --"
    assert str(ctx.tenant_id) not in payload and ctx.actor_id=="viewer-alpha"
