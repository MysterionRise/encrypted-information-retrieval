# Retrieval Benchmark Report

Documents: 10000
Tenant: benchmark-tenant

| Operation | Mean latency |
| --- | ---: |
| Ingest all documents | 11339.41 ms |
| Search fraud controls | 17.85 ms |
| Decrypt one document | 0.94 ms |
| RAG retrieve top 10 with plaintext | 33.57 ms |

Matches returned: 25
RAG candidates returned: 10

Leakage note: this benchmark uses deterministic keyword tokens. The server can
observe token equality, query repetition, access patterns, and result sizes.
