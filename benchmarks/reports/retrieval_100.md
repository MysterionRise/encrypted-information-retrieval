# Retrieval Benchmark Report

Documents: 100
Tenant: benchmark-tenant

| Operation | Mean latency |
| --- | ---: |
| Ingest all documents | 123.25 ms |
| Search fraud controls | 1.20 ms |
| Decrypt one document | 1.07 ms |
| RAG retrieve top 10 with plaintext | 10.58 ms |

Matches returned: 20
RAG candidates returned: 10

Leakage note: this benchmark uses deterministic keyword tokens. The server can
observe token equality, query repetition, access patterns, and result sizes.
