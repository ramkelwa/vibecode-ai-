"""Application configuration loaded from environment variables.

All secrets and tunables come from the environment - nothing is hardcoded.
See backend/.env.example for the full list of supported variables.
"""

from __future__ import annotations

from functools import lru_cache
from typing import List

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- Application ---
    APP_NAME: str = "VibeShield AI"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    API_V1_PREFIX: str = "/api"
    CORS_ORIGINS: str = (
        "http://localhost:5173,http://localhost:3000,"
        "https://vibecode-ai-five.vercel.app"
    )

    # --- Database ---
    DATABASE_URL: str = "sqlite:///./vibeshield.db"

    # --- Auth / RBAC ---
    SECRET_KEY: str = "change-me-in-production-use-a-long-random-string"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480

    FIRST_ADMIN_NAME: str = "Security Analyst"
    FIRST_ADMIN_EMAIL: str = "admin@vibeshield.local"
    FIRST_ADMIN_PASSWORD: str = "ChangeMe123!"
    FIRST_ADMIN_ROLE: str = "admin"

    # --- Scanning safety controls ---
    SCAN_REQUEST_TIMEOUT: int = 15
    SCAN_TOTAL_TIMEOUT: int = 900
    SCAN_MAX_REQUESTS_PER_TARGET: int = 250
    SCAN_REQUESTS_PER_SECOND: float = 4.0
    SCAN_ALLOW_PRIVATE_TARGETS: bool = True
    SCAN_MAX_CONCURRENCY: int = 4

    # --- AI analysis layer ---
    AI_PROVIDER: str = "offline"
    AI_MODEL: str = "gpt-4o-mini"
    AI_BASE_URL: str = "https://openrouter.ai/api/v1"
    AI_API_KEY: str = ""
    AI_MAX_FINDINGS_TO_EXPLAIN: int = 40

    # --- AI provider abstraction ---
    # Provider family: "offline" (no AI) | "glm" | "openai_compat" | "provider_custom"
    AI_PROVIDER_FAMILY: str = "offline"
    # For provider_custom: base path (no trailing slash) and auth scheme/headers
    # when the provider requires them. Leave fields unset when provider is offline/
    # GLM/openai-compatible and the standard fields above apply.
    AI_PROVIDER_BASE_URL: str = "https://openrouter.ai/api/v1"
    AI_PROVIDER_AUTH_TYPE: str = "bearer"
    AI_PROVIDER_AUTH_KEY_ENV: str = "AI_API_KEY"  # env var holding the provider key

    # --- Optional external tools ---
    ENABLE_EXTERNAL_TOOLS: bool = True
    ZAP_API_URL: str = ""
    ZAP_API_KEY: str = ""
    NUCLEI_PATH: str = "nuclei"
    NMAP_PATH: str = "nmap"
    SEMGREP_PATH: str = "semgrep"

    # --- Phase 4: dependency audit / source analysis ---
    NPM_COMMAND: str = "npm"
    PIP_AUDIT_COMMAND: str = "pip-audit"
    TOOL_EXECUTION_TIMEOUT: int = 180
    DEPENDENCY_SCAN_TOOL_TIMEOUT: int = 180
    SEMGREP_TIMEOUT: int = 300
    ZAP_SAFE_MODE: bool = True
    ZAP_SCAN_MAX_DURATION: int = 1800
    AUTHORIZED_PROJECT_ROOTS: str = ""  # comma-separated absolute dirs

    @field_validator("SCAN_REQUESTS_PER_SECOND")
    @classmethod
    def _min_rate(cls, v: float) -> float:
        # Never allow an unbounded request rate.
        return max(0.1, min(v, 20.0))

    @property
    def cors_origin_list(self) -> List[str]:
        configured = [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]
        production_frontend = "https://vibecode-ai-five.vercel.app"
        return list(dict.fromkeys([*configured, production_frontend]))

    @property
    def authorized_project_roots(self) -> List[str]:
        return [p.strip() for p in self.AUTHORIZED_PROJECT_ROOTS.split(",") if p.strip()]

    @property
    def is_sqlite(self) -> bool:
        return self.DATABASE_URL.startswith("sqlite")


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
