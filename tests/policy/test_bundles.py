from uuid import uuid4
import pytest
from app.policy.bundles import BundleStatus,PolicyBundle,SimulationCase,simulate


def test_four_eyes_policy_activation_and_simulation():
    b=PolicyBundle(uuid4(),"4.0",{"allowed_operations":["READ"],"max_classification":1},"author")
    with pytest.raises(PermissionError): b.approve("author")
    b.approve("reviewer"); b.activate(); assert b.status==BundleStatus.ACTIVE
    result=simulate(b,[SimulationCase({"operation":"READ","classification":1},"ALLOW"),SimulationCase({"operation":"READ","classification":3},"DENY")])
    assert result["valid"]
