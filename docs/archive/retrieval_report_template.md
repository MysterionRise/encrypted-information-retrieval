# Retrieval Benchmark Report Template

Run:

```bash
python -m encrypted_ir.tools.benchmark_retrieval \
  --database-url sqlite+pysqlite:///:memory: \
  --documents 1000 \
  --report benchmarks/reports/latest_retrieval.md
```

## Summary

| Operation | Mean latency |
| --- | ---: |
| Ingest all documents | TBD |
| Search keyword query | TBD |
| Decrypt one document | TBD |
| RAG retrieve top K | TBD |

## Security Checks

| Check | Result |
| --- | --- |
| Tenant isolation | TBD |
| Persistence after API restart | TBD |
| Audit rows written | TBD |
| Plaintext absent from audit records | TBD |

## Leakage Notes

The durable RAG workflow uses AES-GCM for document confidentiality and
deterministic HMAC keyword tokens for retrieval. Expected leakage includes
token equality, query repetition, access patterns, and result sizes. This is
acceptable for the prototype demo but must be reviewed against production data
sensitivity and threat model before deployment.
