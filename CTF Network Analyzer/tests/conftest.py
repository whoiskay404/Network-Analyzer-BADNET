"""Shared fixtures for the BADNET test suite."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _have_tshark() -> bool:
    from badnet.integrations.system_tools import detect_all

    return detect_all().tshark.found


requires_tshark = pytest.mark.skipif(not _have_tshark(), reason="tshark is not installed")


@pytest.fixture(scope="session")
def project_root() -> Path:
    """The repository root."""
    return PROJECT_ROOT


def generate_sample(target_dir: Path) -> Path:
    """Generate the synthetic capture into *target_dir* and return its path."""
    import os
    import subprocess
    import sys

    generator = PROJECT_ROOT / "tools" / "make_sample_pcap.py"
    if not generator.exists():
        pytest.skip("sample generator is missing")
    target_dir.mkdir(parents=True, exist_ok=True)
    out = target_dir / "sample.pcap"
    result = subprocess.run(
        [sys.executable, str(generator), str(out)],
        capture_output=True,
        text=True,
        cwd=str(PROJECT_ROOT),
        env={**os.environ, "PYTHONPATH": str(PROJECT_ROOT)},
    )
    if result.returncode != 0:
        pytest.fail(f"sample generation failed: {result.stderr[-2000:]}")
    return out


@pytest.fixture(scope="session")
def sample_pcap(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A freshly generated synthetic capture (deterministic)."""
    return generate_sample(tmp_path_factory.mktemp("sample"))


@pytest.fixture(scope="session")
def committed_sample() -> Path:
    """The checked-in sample capture, if present."""
    path = PROJECT_ROOT / "examples" / "sample.pcap"
    if not path.exists():
        pytest.skip("examples/sample.pcap has not been generated")
    return path


@pytest.fixture
def output_dir(tmp_path: Path) -> Path:
    """An empty directory for case output."""
    target = tmp_path / "out"
    target.mkdir()
    return target


@pytest.fixture
def in_tmp(tmp_path: Path) -> Path:
    """Alias making the temporary directory explicit in tests."""
    return tmp_path


@pytest.fixture
def have_tool():
    """Return a predicate telling whether an external tool exists."""
    return lambda name: shutil.which(name) is not None
