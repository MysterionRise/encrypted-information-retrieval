"""Deterministic local portfolio demo for encrypted retrieval primitives.

Run from the repository root with:
    PYTHONPATH=src python3.11 examples/portfolio_demo.py
"""

from __future__ import annotations

import json
from typing import Any

from encrypted_ir.audit import AuditEventType
from encrypted_ir.blind_index import BlindIndexConfig, BlindIndexSearch
from encrypted_ir.key_manager import KeyManager
from encrypted_ir.ore import ORE
from encrypted_ir.searchable import SearchableEncryption


def _blind_index_demo() -> dict[str, Any]:
    master_key = b"B" * 32
    config = BlindIndexConfig(field_name="account_number", case_sensitive=True)
    records = {
        "cust-001": {"account_number": "ACC-1001", "segment": "commercial"},
        "cust-002": {"account_number": "ACC-2002", "segment": "retail"},
    }

    tenant_a = BlindIndexSearch("tenant-alpha", master_key)
    tenant_b = BlindIndexSearch("tenant-beta", master_key)
    tenant_a_indexes = tenant_a.index_records(records, "account_number", config)

    tenant_a_index = tenant_a.generator.create_index("ACC-1001", config)
    tenant_b_index = tenant_b.generator.create_index("ACC-1001", config)

    return {
        "tenant_scope": ["tenant-alpha", "tenant-beta"],
        "same_value_cross_tenant_equal": tenant_a_index == tenant_b_index,
        "tenant_alpha_match": tenant_a.search("ACC-1001", tenant_a_indexes, config),
        "blind_index_bytes": config.output_length,
    }


def _encrypted_document_demo() -> dict[str, Any]:
    cipher = SearchableEncryption(encryption_key=b"E" * 32, search_key=b"S" * 32)
    documents = {
        "risk-001": "Quarterly fraud risk controls for regulated RAG retrieval.",
        "risk-002": "Customer complaint workflow with privacy preserving search.",
        "risk-003": "Treasury liquidity memo for board reporting.",
    }
    encrypted_store = {}
    token_store = {}
    for doc_id, content in documents.items():
        encrypted_doc, tokens = cipher.encrypt_document(content)
        encrypted_store[doc_id] = encrypted_doc
        token_store[doc_id] = tokens

    query_token = cipher.generate_search_query("fraud")
    matches = sorted(doc_id for doc_id, tokens in token_store.items() if query_token in tokens)
    authorized_context = cipher.decrypt_document(encrypted_store[matches[0]]).decode("utf-8")

    return {
        "query": "fraud",
        "matched_doc_ids": matches,
        "encrypted_payload_bytes": {
            doc_id: len(value) for doc_id, value in encrypted_store.items()
        },
        "index_contains_plaintext": any(
            b"fraud" in encrypted_doc.lower() for encrypted_doc in encrypted_store.values()
        ),
        "authorized_context_doc_id": matches[0],
        "authorized_context_preview": authorized_context[:44],
    }


def _ore_range_demo() -> dict[str, Any]:
    ore = ORE(key=b"O" * 32)
    amounts = {
        "txn-001": 750,
        "txn-002": 1250,
        "txn-003": 4100,
        "txn-004": 9800,
    }
    encrypted_amounts = {txn_id: ore.encrypt_int(amount) for txn_id, amount in amounts.items()}
    min_ciphertext = ore.encrypt_int(1000)
    max_ciphertext = ore.encrypt_int(5000)
    in_range = set(
        ore.range_query(
            list(encrypted_amounts.values()),
            min_val=min_ciphertext,
            max_val=max_ciphertext,
        )
    )
    byte_sort_order = sorted(encrypted_amounts, key=lambda txn_id: encrypted_amounts[txn_id])
    plaintext_sort_order = sorted(amounts, key=lambda txn_id: amounts[txn_id])

    return {
        "range": {"min": 1000, "max": 5000},
        "matched_txn_ids": sorted(
            txn_id for txn_id, ct in encrypted_amounts.items() if ct in in_range
        ),
        "pairwise_compare_txn_002_vs_txn_003": ore.compare(
            encrypted_amounts["txn-002"],
            encrypted_amounts["txn-003"],
        ),
        "raw_ciphertext_sort_matches_plaintext_sort": byte_sort_order == plaintext_sort_order,
    }


def _key_lifecycle_demo() -> dict[str, Any]:
    manager = KeyManager(master_key=b"M" * 32)
    old_key_id = manager.create_key(
        "document_search",
        key_size=32,
        rotation_period_days=30,
        description="Portfolio demo search-token key",
    )
    manager.get_key(old_key_id)
    new_key_id = manager.rotate_key(old_key_id)

    audit_operations = [entry["operation"] for entry in manager.get_audit_log(limit=10)]
    return {
        "created_key_type": manager.get_metadata(new_key_id).key_type,
        "old_key_state": manager.get_metadata(old_key_id).lifecycle_state,
        "new_key_active": manager.get_metadata(new_key_id).active,
        "active_key_count": len(manager.list_keys(key_type="document_search")),
        "audit_operations_latest_first": audit_operations,
    }


def build_demo_summary() -> dict[str, Any]:
    """Build a deterministic summary suitable for screenshots and smoke tests."""
    encrypted_documents = _encrypted_document_demo()
    return {
        "demo": "encrypted-ir-portfolio",
        "mode": "local-in-process",
        "network_required": False,
        "external_kms_required": False,
        "blind_indexes": _blind_index_demo(),
        "encrypted_document_search": encrypted_documents,
        "ore_range_query": _ore_range_demo(),
        "key_and_audit_lifecycle": _key_lifecycle_demo(),
        "ai_retrieval_narrative": {
            "model_call_performed": False,
            "candidate_doc_ids": encrypted_documents["matched_doc_ids"],
            "privacy_boundary": (
                "Search runs over deterministic tokens; plaintext is decrypted only for an "
                "authorized retrieval context."
            ),
            "auditable_events": [
                AuditEventType.SEARCH_KEYWORD.value,
                AuditEventType.DECRYPT.value,
                AuditEventType.KEY_ROTATE.value,
            ],
        },
        "production_claim": "prototype, not production-certified cryptography",
    }


def main() -> int:
    """Print the demo JSON summary."""
    print(json.dumps(build_demo_summary(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
