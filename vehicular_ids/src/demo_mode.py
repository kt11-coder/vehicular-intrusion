"""Public-demo mode helpers for safe Streamlit deployment defaults."""

from __future__ import annotations

import os
from typing import Mapping

from utils.config import PUBLIC_DEMO_MODE_ENV


def public_demo_mode_enabled(secrets: Mapping[str, object] | None = None) -> bool:
    """Return True when public demo mode should disable write-heavy/risky controls."""
    env_value = os.getenv(PUBLIC_DEMO_MODE_ENV)
    if env_value is not None:
        return env_value.strip().lower() in {"1", "true", "yes", "on"}

    if secrets and PUBLIC_DEMO_MODE_ENV in secrets:
        return str(secrets[PUBLIC_DEMO_MODE_ENV]).strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }

    return False
