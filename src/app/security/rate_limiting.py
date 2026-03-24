"""Rate limiting configuration for API endpoints."""

from __future__ import annotations

import asyncio
import inspect
from typing import Any, cast

from slowapi import Limiter
from slowapi.util import get_remote_address

# Compatibility shim for SlowAPI on Python 3.14+.
# SlowAPI still calls asyncio.iscoroutinefunction, which emits a deprecation warning.
# Rebinding avoids warning noise (including -W error runs) until upstream is updated.
setattr(asyncio, "iscoroutinefunction", cast(Any, inspect.iscoroutinefunction))

limiter = Limiter(key_func=get_remote_address)

POST_SCANS_RATE_LIMIT = "10/minute"
GET_FINDINGS_RATE_LIMIT = "30/minute"
