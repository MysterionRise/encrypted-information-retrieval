"""The documented IAM policies must match what the code sends to KMS (docs/KMS_DEPLOYMENT.md)."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from encrypted_ir.master_key import master_key_encryption_context

IAM_DIR = Path(__file__).resolve().parent.parent / "docs" / "iam"
KEY_ARN = re.compile(r"^arn:aws:kms:[^:]+:[^:]+:key/[^/*]+$")


def _statements(name: str) -> dict[str, dict]:
    policy = json.loads((IAM_DIR / name).read_text())
    assert policy["Version"] == "2012-10-17"
    return {statement["Sid"]: statement for statement in policy["Statement"]}


def _expected_condition() -> dict:
    context = master_key_encryption_context("prod")
    return {"StringEquals": {f"kms:EncryptionContext:{k}": v for k, v in context.items()}}


@pytest.mark.parametrize("name", ["kms-api-runtime-policy.json", "kms-operator-policy.json"])
def test_every_statement_allows_one_action_on_one_key_arn(name):
    for statement in _statements(name).values():
        assert statement["Effect"] == "Allow"
        assert isinstance(statement["Action"], str) and "*" not in statement["Action"]
        # A key ARN, never an alias or a wildcard: alias ARNs do not match key operations.
        assert KEY_ARN.match(statement["Resource"]), statement["Resource"]


def test_api_runtime_role_can_only_decrypt_with_the_master_key_context():
    statements = _statements("kms-api-runtime-policy.json")

    assert [s["Action"] for s in statements.values()] == ["kms:Decrypt"]
    [decrypt] = statements.values()
    assert decrypt["Condition"] == _expected_condition()


def test_operator_role_wraps_with_the_context_and_describes_without_one():
    statements = _statements("kms-operator-policy.json")
    by_action = {s["Action"]: s for s in statements.values()}

    assert set(by_action) == {"kms:GenerateDataKey", "kms:DescribeKey"}
    assert by_action["kms:GenerateDataKey"]["Condition"] == _expected_condition()
    # DescribeKey sends no encryption context, so a context condition would always deny it.
    assert "Condition" not in by_action["kms:DescribeKey"]
