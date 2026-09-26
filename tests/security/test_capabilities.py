from datetime import datetime, timedelta, timezone

import pytest

from app.security.capabilities import Capability, require_capability
from app.security.context import Classification, Operation
from tests.conftest import context


def test_expired_capability_denied():
    ctx=context("alpha-agent")
    cap=Capability(ctx.agent_id,ctx.tenant_id,frozenset({"regulatory_search"}),frozenset({Operation.SEARCH}),Classification.INTERNAL,datetime.now(timezone.utc)-timedelta(seconds=1))
    with pytest.raises(PermissionError): require_capability(cap,ctx,"regulatory_search",Operation.SEARCH)
