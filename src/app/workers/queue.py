from uuid import uuid4


def enqueue_scan(scan_id: int) -> str:
    # Placeholder queue adapter for day-3 orchestration.
    return f"scan-{scan_id}-{uuid4().hex[:12]}"
