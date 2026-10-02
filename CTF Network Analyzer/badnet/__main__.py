"""Allow ``python -m badnet`` in addition to the ``badnet`` console script."""

from __future__ import annotations

from badnet.cli import run

if __name__ == "__main__":  # pragma: no cover - exercised via subprocess only
    run()
