#!/usr/bin/env python3
"""Compare a pytest-benchmark JSON report with the committed baseline.

Usage::

    python scripts/compare_benchmarks.py benchmarks/results/latest.json
    python scripts/compare_benchmarks.py benchmarks/results/latest.json --update

Each benchmark's median is compared with its median in ``benchmarks/baseline.json``. A
benchmark more than ``--threshold`` times slower (default 3.0) is reported as a regression and
the script exits 1. The threshold is generous on purpose: shared CI runners vary by 20-30%
between runs, so only a large slowdown is a signal. Benchmarks missing from either side are
listed but do not fail. ``--update`` writes the report's medians as the new baseline.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

DEFAULT_BASELINE = Path(__file__).resolve().parents[1] / "benchmarks" / "baseline.json"


def medians(report: dict) -> dict[str, float]:
    """``{fullname: median seconds}`` from a pytest-benchmark JSON report."""
    return {bench["fullname"]: float(bench["stats"]["median"]) for bench in report["benchmarks"]}


def compare(
    current: dict[str, float], baseline: dict[str, float], threshold: float
) -> tuple[list[str], list[str]]:
    """Return (report lines, regressions)."""
    lines = [f"{'ratio':>7}  {'median':>12}  {'baseline':>12}  benchmark"]
    regressions = []
    for name in sorted(set(current) | set(baseline)):
        if name not in baseline:
            lines.append(f"{'new':>7}  {current[name]:>12.6f}  {'-':>12}  {name}")
            continue
        if name not in current:
            lines.append(f"{'missing':>7}  {'-':>12}  {baseline[name]:>12.6f}  {name}")
            continue
        ratio = current[name] / baseline[name] if baseline[name] > 0 else float("inf")
        flag = "  REGRESSION" if ratio > threshold else ""
        lines.append(
            f"{ratio:>7.2f}  {current[name]:>12.6f}  {baseline[name]:>12.6f}  {name}{flag}"
        )
        if ratio > threshold:
            regressions.append(name)
    return lines, regressions


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("report", type=Path, help="pytest-benchmark JSON report")
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    parser.add_argument("--threshold", type=float, default=3.0, help="slowdown factor that fails")
    parser.add_argument("--update", action="store_true", help="write the report as the baseline")
    args = parser.parse_args(argv)

    current = medians(json.loads(args.report.read_text()))
    if args.update:
        args.baseline.write_text(
            json.dumps(
                {
                    "generated": datetime.now(UTC).isoformat(timespec="seconds"),
                    "statistic": "median seconds",
                    "benchmarks": dict(sorted(current.items())),
                },
                indent=2,
            )
            + "\n"
        )
        print(f"wrote {len(current)} medians to {args.baseline}")
        return 0

    baseline = json.loads(args.baseline.read_text())["benchmarks"]
    lines, regressions = compare(current, baseline, args.threshold)
    print("\n".join(lines))
    if regressions:
        print(f"\n{len(regressions)} benchmark(s) more than {args.threshold}x slower than baseline")
        return 1
    print(f"\nno benchmark more than {args.threshold}x slower than baseline")
    return 0


if __name__ == "__main__":
    sys.exit(main())
