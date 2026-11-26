from __future__ import annotations

__all__ = ["healthcheck"]


def healthcheck() -> str:
    """Return service liveness status."""
    return "ok"
