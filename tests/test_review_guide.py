"""docs/REVIEW_GUIDE.md must point only at proofs that exist (issue #51).

Every backticked test ID must name a real test, every backticked repository path must exist,
every `CI `job` "step"` must be a job and step of .github/workflows/ci.yml, and every line of the
README's "What Is Real" list must have a row in the guide.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
GUIDE = (ROOT / "docs" / "REVIEW_GUIDE.md").read_text()
CI = (ROOT / ".github" / "workflows" / "ci.yml").read_text()

TEST_ID = re.compile(r"`(tests/[\w/]+\.py)::([\w:]+)`")
PATH = re.compile(r"`((?:src|scripts|docs|deploy|benchmarks|tests|\.github)/[\w./-]+|Dockerfile)`")
CI_JOB = re.compile(r'CI `([\w-]+)`(?: "([^"]+)")?')


def _definitions(path: Path) -> set[str]:
    """``name`` for each top-level test and ``Class::method`` for each method."""
    tree = ast.parse(path.read_text())
    names = set()
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            names.add(node.name)
        elif isinstance(node, ast.ClassDef):
            names.add(node.name)
            for item in node.body:
                if isinstance(item, ast.FunctionDef | ast.AsyncFunctionDef):
                    names.add(f"{node.name}::{item.name}")
    return names


def _ci_jobs() -> set[str]:
    jobs = CI.split("\njobs:\n", 1)[1]
    return set(re.findall(r"^  ([\w-]+):\s*$", jobs, flags=re.MULTILINE))


def _ci_step_names() -> set[str]:
    return {name.strip() for name in re.findall(r"^\s+- name: (.+)$", CI, flags=re.MULTILINE)}


TEST_IDS = sorted(set(TEST_ID.findall(GUIDE)))


def test_the_guide_cites_tests():
    assert len(TEST_IDS) > 50


@pytest.mark.parametrize(("path", "name"), TEST_IDS, ids=[f"{p}::{n}" for p, n in TEST_IDS])
def test_every_cited_test_exists(path, name):
    file = ROOT / path
    assert file.exists(), path
    assert name in _definitions(file), f"{path}::{name}"


def test_every_cited_path_exists():
    missing = [p for p in sorted(set(PATH.findall(GUIDE))) if not (ROOT / p).exists()]
    assert missing == []


def test_every_cited_ci_job_and_step_exists():
    jobs, steps = _ci_jobs(), _ci_step_names()
    cited = CI_JOB.findall(GUIDE)
    assert cited
    assert sorted({job for job, _ in cited} - jobs) == []
    assert sorted({step for _, step in cited if step} - steps) == []


def test_every_what_is_real_line_has_a_row():
    readme = (ROOT / "README.md").read_text()
    section = readme.split("## What Is Real", 1)[1].split("\n## ", 1)[0]
    claims = [line[2:].strip() for line in section.splitlines() if line.startswith("- ")]
    assert claims
    rows = {line.split("|")[1].strip() for line in GUIDE.splitlines() if line.startswith("| ")}
    assert [claim for claim in claims if claim not in rows] == []
