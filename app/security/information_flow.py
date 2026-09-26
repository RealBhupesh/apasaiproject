from __future__ import annotations

from dataclasses import dataclass

from app.security.context import Classification


@dataclass(frozen=True)
class LabeledValue:
    value: object
    classification: Classification
    tenant_id: str


def join_classification(*levels: Classification) -> Classification:
    return max(levels, default=Classification.PUBLIC)


def derive(values: list[LabeledValue], output: object) -> LabeledValue:
    tenants = {v.tenant_id for v in values}
    if len(tenants) != 1:
        raise PermissionError("cross-tenant derivation forbidden")
    return LabeledValue(output, join_classification(*(v.classification for v in values)), tenants.pop())
