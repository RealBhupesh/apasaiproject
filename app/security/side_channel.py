from __future__ import annotations

import asyncio
import secrets
from dataclasses import dataclass


@dataclass(frozen=True)
class PublicDenial:
    status_code: int = 403
    message: str = "Request denied by policy"
    retryable: bool = False


async def bounded_denial_delay(minimum_ms: int = 18, jitter_ms: int = 8) -> None:
    """Small bounded jitter reduces obvious existence timing without claiming constant time."""
    await asyncio.sleep((minimum_ms + secrets.randbelow(jitter_ms + 1)) / 1000)
