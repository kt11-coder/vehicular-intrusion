"""Dashboard authentication helpers."""

from __future__ import annotations

import os
from typing import Mapping, Tuple

from utils.config import (
    AUTH_ENABLED_ENV,
    AUTH_PASSWORD_ENV,
    AUTH_USERNAME_ENV,
    DEMO_AUTH_PASSWORD,
    DEMO_AUTH_USERNAME,
    PUBLIC_DEMO_MODE_ENV,
)


def auth_is_enabled(secrets: Mapping[str, object] | None = None) -> bool:
    """Return whether dashboard authentication should be enforced."""
    public_demo_env = os.getenv(PUBLIC_DEMO_MODE_ENV)
    if public_demo_env is not None and public_demo_env.strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }:
        return False

    env_value = os.getenv(AUTH_ENABLED_ENV)
    if env_value is not None:
        return env_value.strip().lower() not in {"0", "false", "no", "off"}

    if secrets and AUTH_ENABLED_ENV in secrets:
        return str(secrets[AUTH_ENABLED_ENV]).strip().lower() not in {
            "0",
            "false",
            "no",
            "off",
        }

    return True


def get_credentials(secrets: Mapping[str, object] | None = None) -> Tuple[str, str]:
    """Resolve the expected dashboard username/password."""
    username = os.getenv(AUTH_USERNAME_ENV)
    password = os.getenv(AUTH_PASSWORD_ENV)

    if not username and secrets and AUTH_USERNAME_ENV in secrets:
        username = str(secrets[AUTH_USERNAME_ENV])
    if not password and secrets and AUTH_PASSWORD_ENV in secrets:
        password = str(secrets[AUTH_PASSWORD_ENV])

    return (
        username or DEMO_AUTH_USERNAME,
        password or DEMO_AUTH_PASSWORD,
    )


def verify_credentials(
    supplied_username: str,
    supplied_password: str,
    secrets: Mapping[str, object] | None = None,
) -> bool:
    """Check provided credentials against configured secrets/env values."""
    expected_username, expected_password = get_credentials(secrets)
    return (
        supplied_username.strip() == expected_username
        and supplied_password == expected_password
    )
