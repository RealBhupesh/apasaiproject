from __future__ import annotations

import os
from dataclasses import dataclass
from enum import StrEnum


class RuntimeMode(StrEnum):
    DEMO = "demo"
    PRODUCTION = "production"


@dataclass(frozen=True)
class Settings:
    runtime_mode: RuntimeMode
    database_url: str | None
    auth_database_url: str | None
    oidc_issuer: str | None
    oidc_audience: str | None
    oidc_public_key: str | None
    evidence_signing_private_key: str | None

    @classmethod
    def from_env(cls) -> "Settings":
        try:
            mode = RuntimeMode(os.getenv("APAS_RUNTIME_MODE", "demo").lower())
        except ValueError as exc:
            raise RuntimeError("APAS_RUNTIME_MODE must be demo or production") from exc
        settings = cls(
            mode,
            os.getenv("DATABASE_URL"),
            os.getenv("AUTH_DATABASE_URL"),
            os.getenv("OIDC_ISSUER"),
            os.getenv("OIDC_AUDIENCE"),
            os.getenv("OIDC_PUBLIC_KEY"),
            os.getenv("EVIDENCE_SIGNING_PRIVATE_KEY"),
        )
        if mode == RuntimeMode.PRODUCTION:
            missing = [
                key
                for key, value in {
                    "DATABASE_URL": settings.database_url,
                    "AUTH_DATABASE_URL": settings.auth_database_url,
                    "OIDC_ISSUER": settings.oidc_issuer,
                    "OIDC_AUDIENCE": settings.oidc_audience,
                    "OIDC_PUBLIC_KEY": settings.oidc_public_key,
                    "EVIDENCE_SIGNING_PRIVATE_KEY": settings.evidence_signing_private_key,
                }.items()
                if not value
            ]
            if missing:
                raise RuntimeError(
                    "production security dependencies missing: " + ", ".join(missing)
                )
        return settings