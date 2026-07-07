# Retrieval Benchmark Report

Documents: 1000
Tenant: benchmark-tenant

| Operation | Mean latency |
| --- | ---: |
| Ingest all documents | 1132.36 ms |
| Search fraud controls | 2.39 ms |
| Decrypt one document | 0.96 ms |
| RAG retrieve top 10 with plaintext | 11.99 ms |

Matches returned: 25
RAG candidates returned: 10

Leakage note: this benchmark uses deterministic keyword tokens. The server can
observe token equality, query repetition, access patterns, and result sizes.
