"""Rotate a tenant's document and search keys and re-encrypt its documents.

Usage::

    python -m encrypted_ir.tools.rotate_tenant_keys --tenant TENANT [--batch-size N]
        [--max-batches N] [--resume]

The database URL and master key come from the same ``ENCRYPTED_IR_*`` environment variables the
API uses; run it while the API keeps serving. It prints a JSON report to stdout. See
:mod:`encrypted_ir.rotation` and ADR-018 for what happens to documents and keys.

Exit codes:
    0  rotation complete
    1  configuration error, or a rotation is already in progress (use --resume) or missing
    2  some documents did not decrypt; no key was retired and the rotation stays in progress
    3  not finished (stopped by --max-batches, or concurrent writes kept adding documents
       under the old keys); run again with --resume to continue
"""

from __future__ import annotations

import argparse
import json
import sys

from encrypted_ir.database import create_database_engine
from encrypted_ir.rotation import RotationError, rotate_tenant_keys
from encrypted_ir.tools._settings import load_settings_and_master_key

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_UNREADABLE = 2
EXIT_STOPPED = 3


def _positive(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Rotate a tenant's keys and re-encrypt its documents."
    )
    parser.add_argument("--tenant", required=True, help="Tenant ID")
    parser.add_argument(
        "--batch-size", type=_positive, default=100, help="Documents per transaction"
    )
    parser.add_argument(
        "--max-batches",
        type=_positive,
        help="Stop after this many batches; continue later with --resume",
    )
    parser.add_argument(
        "--resume", action="store_true", help="Continue the tenant's rotation in progress"
    )
    args = parser.parse_args(argv)

    try:
        settings, master_key = load_settings_and_master_key()
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    engine = create_database_engine(settings.database_url)
    try:
        report = rotate_tenant_keys(
            engine,
            master_key,
            args.tenant,
            batch_size=args.batch_size,
            resume=args.resume,
            max_batches=args.max_batches,
        )
    except RotationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    finally:
        engine.dispose()

    print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    if report.failed_documents:
        print(
            f"error: {report.failed_documents} document(s) did not decrypt; no key was retired",
            file=sys.stderr,
        )
        return EXIT_UNREADABLE
    if not report.complete:
        reason = "stopped by --max-batches" if report.stopped_early else "documents still moving"
        print(f"{reason}; run again with --resume to continue", file=sys.stderr)
        return EXIT_STOPPED
    if report.unverified_documents:
        print(
            f"note: {report.unverified_documents} document(s) keep an old search key because "
            "their keywords could not be verified; ingest them again to move them",
            file=sys.stderr,
        )
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
