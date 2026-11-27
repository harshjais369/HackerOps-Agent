from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator
from typing import List, Union
import json
import os

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "HackerOps Agent"
    environment: str = "development"
    debug: bool = True

    # LLM Settings (LiteLLM)
    llm_api_key: str = ""
    llm_model: str = "gemini/gemini-2.5-flash"

    # Database
    database_url: str = "sqlite+aiosqlite:///./hackerops.db"

    # Safety Guardrails
    allow_local_targets: bool = False

    # Docker Sandbox Settings
    docker_sandbox_image: str = "hackerops-sandbox:latest"
    sandbox_timeout_seconds: int = 45
    sandbox_mem_limit: str = "512m"
    sandbox_cpu_quota: int = 50000

    # Redis URL (optional fallback to in-memory)
    redis_url: str = "redis://localhost:6379/0"

    # CORS
    cors_origins: Union[List[str], str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000"
    ]

    @field_validator("cors_origins", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            v_stripped = v.strip()
            if v_stripped.startswith("[") and v_stripped.endswith("]"):
                try:
                    return json.loads(v_stripped)
                except Exception:
                    pass
            # Comma-separated list support (e.g. "http://localhost:3000,http://127.0.0.1:3000")
            return [i.strip() for i in v_stripped.split(",") if i.strip()]
        elif isinstance(v, list):
            return v
        return ["*"]

settings = Settings()
