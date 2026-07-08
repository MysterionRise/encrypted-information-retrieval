"""Smoke tests for the local portfolio demo."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from examples.portfolio_demo import build_demo_summary


def test_portfolio_demo_summary_expected_shape():
    data = build_demo_summary()

    assert data["demo"] == "encrypted-ir-portfolio"
    assert data["network_required"] is False
    assert data["external_kms_required"] is False
    assert data["production_claim"] == "prototype, not production-certified cryptography"
    assert data["blind_indexes"]["same_value_cross_tenant_equal"] is False
    assert data["encrypted_document_search"]["matched_doc_ids"] == ["risk-001"]
    assert data["encrypted_document_search"]["index_contains_plaintext"] is False
    assert data["ore_range_query"]["matched_txn_ids"] == ["txn-002", "txn-003"]
    assert data["key_and_audit_lifecycle"]["old_key_state"] == "retired"
    assert data["ai_retrieval_narrative"]["model_call_performed"] is False


def test_portfolio_demo_exits_successfully_and_emits_json():
    root = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    env["PYTHONPATH"] = f"{root / 'src'}:{env.get('PYTHONPATH', '')}"

    result = subprocess.run(  # noqa: S603
        [sys.executable, str(root / "examples" / "portfolio_demo.py")],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )

    data = json.loads(result.stdout)
    assert data["demo"] == "encrypted-ir-portfolio"
    assert set(data) >= {
        "blind_indexes",
        "encrypted_document_search",
        "ore_range_query",
        "key_and_audit_lifecycle",
        "ai_retrieval_narrative",
    }
