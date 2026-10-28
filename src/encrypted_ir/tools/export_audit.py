"""Export and verify one tenant's audit chain.

Usage::

    python -m encrypted_ir.tools.export_audit --tenant TENANT [--since ISO] [--output FILE]
        [--check-head SEQ:HASH]

The database URL and master key come from the same ``ENCRYPTED_IR_*`` environment variables the
API uses. The whole chain is always verified from its first entry, even with ``--since``, which
only filters the rows written out. Each output line is one JSON object: the hashed entry plus
``prev_hash`` and ``entry_hash``. Rows are written even when verification fails, so a broken
chain can be inspected.

The verified head (``seq`` and hash) is printed to stderr. Store it somewhere the database's
writers cannot change, and pass it back with ``--check-head`` on a later export: someone who
can write the database can truncate the chain and rewrite the head row to match, but cannot
remove an entry that an earlier head already committed to without breaking this check.

Exit codes: 0 verified, 1 configuration error, 2 the chain or the ``--check-head`` check failed.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from typing import IO, Any

from sqlalchemy import func, select

from encrypted_ir import audit
from encrypted_ir.database import audit_log_table, create_database_engine
from encrypted_ir.tools._settings import load_settings_and_master_key

EXIT_OK = 0
EXIT_CONFIG = 1
EXIT_BROKEN = 2


def _parse_head(value: str) -> tuple[int, str]:
    seq, sep, digest = value.partition(":")
    if not sep or not seq.isdigit() or int(seq) < 1 or len(digest) != 64:
        raise argparse.ArgumentTypeError("expected SEQ:HASH, e.g. 42:<64 hex characters>")
    try:
        bytes.fromhex(digest)
    except ValueError:
        raise argparse.ArgumentTypeError("HASH must be 64 hex characters") from None
    return int(seq), digest.lower()


def _parse_since(value: str) -> datetime:
    try:
        since = datetime.fromisoformat(value)
    except ValueError:
        raise argparse.ArgumentTypeError("expected an ISO 8601 timestamp") from None
    if since.tzinfo is None:
        raise argparse.ArgumentTypeError("include a UTC offset, e.g. 2026-10-01T00:00:00+00:00")
    return since


def _export_line(row: Any) -> str:
    return json.dumps(
        {**row.entry_json, "prev_hash": row.prev_hash, "entry_hash": row.entry_hash},
        sort_keys=True,
        ensure_ascii=False,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Export and verify one tenant's audit chain as JSON lines."
    )
    parser.add_argument("--tenant", required=True, help="Tenant ID")
    parser.add_argument(
        "--since", type=_parse_since, help="Only write entries at or after this time"
    )
    parser.add_argument("--output", help="Output file (default: stdout)")
    parser.add_argument(
        "--check-head",
        type=_parse_head,
        metavar="SEQ:HASH",
        help="A head printed by an earlier export that the chain must still contain",
    )
    args = parser.parse_args(argv)

    try:
        settings, master_key = load_settings_and_master_key()
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_CONFIG

    engine = create_database_engine(settings.database_url)
    try:
        with engine.connect() as conn:
            rows, head = audit.load_chain(conn, args.tenant)
            legacy = conn.execute(
                select(func.count())
                .select_from(audit_log_table)
                .where(audit_log_table.c.tenant_id == args.tenant, audit_log_table.c.seq.is_(None))
            ).scalar_one()
    finally:
        engine.dispose()

    result = audit.verify_chain(
        rows, head, args.tenant, audit.derive_audit_key(master_key, args.tenant)
    )

    if args.output:
        with open(args.output, "w", encoding="utf-8") as out:
            _write(out, rows, args.since)
    else:
        _write(sys.stdout, rows, args.since)

    print(
        json.dumps(
            {
                "tenant_id": args.tenant,
                "verified": result.ok,
                "entries": len(rows),
                "head_seq": result.head_seq,
                "head_hash": result.head_hash,
                "unchained_legacy_rows": legacy,
            }
        ),
        file=sys.stderr,
    )
    if not result.ok:
        print(
            f"error: chain broken at seq {result.first_bad_seq}: {result.reason}", file=sys.stderr
        )
        return EXIT_BROKEN
    if args.check_head is not None:
        seq, digest = args.check_head
        if seq > len(rows) or rows[seq - 1].entry_hash != digest:
            print(f"error: the chain no longer contains head {seq}:{digest}", file=sys.stderr)
            return EXIT_BROKEN
    return EXIT_OK


def _write(out: IO[str], rows: list[Any], since: datetime | None) -> None:
    for row in rows:
        if since is not None and datetime.fromisoformat(row.entry_json["timestamp"]) < since:
            continue
        out.write(_export_line(row) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
