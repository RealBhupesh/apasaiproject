from app.security.context import Classification
from app.security.information_flow import LabeledValue,derive
import pytest


def test_derived_output_inherits_highest_classification():
    x=derive([LabeledValue("a",Classification.PUBLIC,"t"),LabeledValue("b",Classification.RESTRICTED,"t")],"summary")
    assert x.classification==Classification.RESTRICTED

def test_cross_tenant_derivation_forbidden():
    with pytest.raises(PermissionError): derive([LabeledValue("a",Classification.PUBLIC,"a"),LabeledValue("b",Classification.PUBLIC,"b")],"x")
