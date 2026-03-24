from __future__ import annotations

import sys
from pathlib import Path


def _bootstrap_path() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    src_path = repo_root / "src"
    if str(src_path) not in sys.path:
        sys.path.insert(0, str(src_path))


def main() -> int:
    _bootstrap_path()
    from app.ci.scan_runner import main as runner_main

    return runner_main()


if __name__ == "__main__":
    raise SystemExit(main())
