"""The research package is quarantined: it warns on import and core code never imports it."""

from __future__ import annotations

import importlib
import os
import subprocess
import sys
from pathlib import Path

import pytest

from encrypted_ir.errors import ResearchPrototypeWarning

SRC = str(Path(__file__).resolve().parents[2] / "src")


def _run_python(*args: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PYTHONPATH": SRC}
    return subprocess.run(  # noqa: S603 - fixed interpreter and arguments
        [sys.executable, *args], capture_output=True, text=True, env=env, timeout=120
    )


def test_core_package_and_api_do_not_import_research():
    result = _run_python(
        "-c",
        "import sys, encrypted_ir, encrypted_ir.api.main; "
        "loaded = sorted(m for m in sys.modules if m.startswith('encrypted_ir.research')); "
        "print(loaded); sys.exit(1 if loaded else 0)",
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_importing_research_warns():
    """With the warning turned into an error, importing the research package fails."""
    result = _run_python(
        "-c",
        "import warnings; "
        "from encrypted_ir.errors import ResearchPrototypeWarning; "
        "warnings.simplefilter('error', ResearchPrototypeWarning); "
        "import encrypted_ir.research",
    )
    assert result.returncode != 0
    assert "ResearchPrototypeWarning" in result.stderr


def test_research_warning_is_a_user_warning():
    research = importlib.import_module("encrypted_ir.research")
    with pytest.warns(ResearchPrototypeWarning, match="unaudited"):
        importlib.reload(research)
    assert issubclass(ResearchPrototypeWarning, UserWarning)


def test_research_classes_are_not_exported_from_the_top_level():
    import encrypted_ir

    for name in ("ORE", "FF1", "BasicHomomorphicEncryption", "MLKEM", "ForwardPrivateSSE"):
        assert name not in encrypted_ir.__all__
        assert not hasattr(encrypted_ir, name)
    assert None not in [getattr(encrypted_ir, name) for name in encrypted_ir.__all__]


@pytest.mark.parametrize(
    ("module", "hidden"),
    [
        ("encrypted_ir.research.homomorphic", ["tenseal"]),
        ("encrypted_ir.research.post_quantum", ["pqcrypto", "pqcrypto.kem", "pqcrypto.sign"]),
    ],
)
def test_missing_research_extra_names_the_extra(monkeypatch, module, hidden):
    for name in hidden:
        monkeypatch.setitem(sys.modules, name, None)
    monkeypatch.delitem(sys.modules, module, raising=False)

    with pytest.raises(ImportError, match=r"research"):
        importlib.import_module(module)
