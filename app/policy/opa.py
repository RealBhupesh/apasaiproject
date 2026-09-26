from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.request import Request, urlopen


@dataclass(frozen=True)
class OPADecision:
    allowed: bool
    decision_id: str | None
    reason: str


class OPAClient:
    """Narrow OPA data-API adapter. It sends attributes, never executable policy from a request."""
    def __init__(self,base_url: str,policy_path: str="apas/authz",timeout_seconds: float=1.0):
        if not base_url.startswith(("http://","https://")): raise ValueError("invalid OPA URL")
        self.url=f"{base_url.rstrip('/')}/v1/data/{policy_path.strip('/')}"; self.timeout=timeout_seconds

    def evaluate(self,attributes: dict)->OPADecision:
        req=Request(self.url,data=json.dumps({"input":attributes}).encode(),headers={"content-type":"application/json"},method="POST")
        with urlopen(req,timeout=self.timeout) as response:
            body=json.load(response).get("result",{})
        return OPADecision(bool(body.get("allow",False)),body.get("decision_id"),str(body.get("reason","policy evaluated")))
