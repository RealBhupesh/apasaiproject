from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class ModelExecutionManifest:
    provider: str
    model: str
    model_version: str
    prompt_hash: str
    tool_schema_hash: str
    temperature: float
    top_p: float
    max_tokens: int
    evidence_order_hash: str
    safety_config_hash: str
    response_hash: str
    deterministic_replay_supported: bool

    @property
    def digest(self) -> str:
        return hashlib.sha256(json.dumps(asdict(self),sort_keys=True,separators=(",", ":")).encode()).hexdigest()
