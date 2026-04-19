"""
GÖZCÜ Configuration Module.

Loads all settings from environment variables (.env file) with sensible defaults.
Provides a single Config dataclass as the source of truth for the entire application.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv


# Resolve project root (two levels up from this file: gozcu/config.py → project root)
PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _load_env() -> None:
    """Load .env file from project root if it exists."""
    env_path = PROJECT_ROOT / ".env"
    if env_path.exists():
        load_dotenv(env_path)
    else:
        # Fallback: try .env.example so the app can start without .env
        example_path = PROJECT_ROOT / ".env.example"
        if example_path.exists():
            load_dotenv(example_path)


def _env_str(key: str, default: str = "") -> str:
    return os.getenv(key, default)


def _env_int(key: str, default: int = 0) -> int:
    raw = os.getenv(key)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_float(key: str, default: float = 0.0) -> float:
    raw = os.getenv(key)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _env_bool(key: str, default: bool = False) -> bool:
    raw = os.getenv(key)
    if raw is None:
        return default
    return raw.strip().lower() in ("true", "1", "yes")


@dataclass(frozen=True)
class Config:
    """Immutable application configuration loaded from environment variables."""

    # --- LLM ---
    LLM_API_KEY: str = field(default_factory=lambda: _env_str("LLM_API_KEY", "lm-studio"))
    LLM_BASE_URL: str = field(default_factory=lambda: _env_str("LLM_BASE_URL", "http://localhost:1234/v1"))
    LLM_MODEL: str = field(default_factory=lambda: _env_str("LLM_MODEL", "local-model"))

    # --- Decision Engine ---
    DECISION_TIMEOUT: int = field(default_factory=lambda: _env_int("DECISION_TIMEOUT", 30))
    HIGH_RISK_THRESHOLD: int = field(default_factory=lambda: _env_int("HIGH_RISK_THRESHOLD", 70))
    AUTONOMOUS_CONFIDENCE_THRESHOLD: float = field(
        default_factory=lambda: _env_float("AUTONOMOUS_CONFIDENCE_THRESHOLD", 0.90)
    )

    # --- Performance ---
    CACHE_TTL_SECONDS: int = field(default_factory=lambda: _env_int("CACHE_TTL_SECONDS", 300))
    CACHE_MAX_SIZE: int = field(default_factory=lambda: _env_int("CACHE_MAX_SIZE", 1024))
    PRE_FILTER_ENABLED: bool = field(default_factory=lambda: _env_bool("PRE_FILTER_ENABLED", True))

    # --- Paths ---
    WHITELIST_PATH: Path = field(
        default_factory=lambda: PROJECT_ROOT / _env_str("WHITELIST_PATH", "data/whitelist.json")
    )
    AUDIT_LOG_PATH: Path = field(
        default_factory=lambda: PROJECT_ROOT / _env_str("AUDIT_LOG_PATH", "logs/audit_trail.jsonl")
    )

    # --- Dashboard ---
    DASHBOARD_HOST: str = field(default_factory=lambda: _env_str("DASHBOARD_HOST", "0.0.0.0"))
    DASHBOARD_PORT: int = field(default_factory=lambda: _env_int("DASHBOARD_PORT", 8080))

    # --- Mode ---
    SIMULATION_MODE: bool = field(default_factory=lambda: _env_bool("SIMULATION_MODE", True))

    def __post_init__(self) -> None:
        """Ensure required directories exist."""
        # Create audit log directory
        self.AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)


# Load environment variables at module import time
_load_env()
