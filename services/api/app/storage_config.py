"""Explicit local storage selection. Never generates or persists a secret key."""
import base64
import os
from pathlib import Path

from app.repository import DevelopmentStore


def create_store():
    mode = os.getenv("ANONFLOW_STORAGE_MODE", "memory")
    if mode == "memory":
        return DevelopmentStore()
    if mode != "sqlite":
        raise RuntimeError("Invalid storage configuration")
    try:
        path = os.environ["ANONFLOW_DB_PATH"]
        key = base64.b64decode(os.environ["ANONFLOW_STORAGE_KEY"], validate=True)
        if (not path.strip() or len(key) != 32 or not Path(path).is_absolute()
                or path.replace("\\", "/").startswith("//") or "://" in path):
            raise ValueError
    except (KeyError, ValueError):
        raise RuntimeError("Invalid storage configuration") from None
    from app.durable_repository import DurableStore
    try:
        return DurableStore(path, key)
    except Exception:
        raise RuntimeError("Storage initialization failed") from None
