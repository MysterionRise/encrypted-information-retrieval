# Privacy-Preserving Retrieval Prototype for Regulated AI/RAG

A portfolio-grade Python prototype for encrypted information retrieval in regulated AI and financial-services settings. The project demonstrates how equality search, keyword retrieval, range queries, key lifecycle controls, and encrypted computation can be composed into RAG-ready privacy infrastructure.

This is **not** an audited production cryptography product. It is a production-oriented implementation demo with explicit leakage notes, tests, Docker Compose, and a durable PostgreSQL-backed retrieval workflow.

## What is Real vs Demo

**Real, working implementation**

- AES-SIV deterministic encryption for equality-search demonstrations
- HMAC blind indexes with tenant-scoped keys
- AES-GCM encrypted document storage with deterministic keyword tokens
- PostgreSQL-backed document/key/audit persistence for the API workflow
- Key lifecycle primitives, file/database storage backends, and AWS KMS abstraction
- TenSEAL-based CKKS examples for encrypted arithmetic
- FastAPI endpoints, Docker Compose, CI, and a broad pytest suite

**Prototype/demo boundaries**

- Custom ORE and forward/private SSE paths are research-backed prototypes, not externally audited cryptographic implementations.
- The local auth layer is suitable for demos and tests; production deployments need real identity, policy, and secret management.
- RAG support is retrieval-only: no embeddings, vector database, or LLM calls are included.
- Legacy `/v1/encrypt`, `/v1/decrypt`, and `/v1/search/*` routes remain compatibility demos; the durable workflow is under `/v1/documents` and `/v1/rag/retrieve`.

## Overview

Based on the comprehensive analysis in [ANALYSIS.md](ANALYSIS.md), this library implements:

- **Deterministic Encryption**: For equality searches on encrypted data
- **Searchable Encryption**: For keyword searches on encrypted documents
- **Order-Preserving Encryption**: For range queries on encrypted numeric data
- **Homomorphic Encryption**: For computations on encrypted data
- **Key Management**: Secure key generation, storage, rotation, and lifecycle management

## Features

- 🔒 **Production-oriented crypto demo**: Uses standard libraries where practical and labels prototype primitives explicitly
- 🔍 **Search capabilities**: Search encrypted data without decryption
- 📊 **Range queries**: Query numeric data while maintaining encryption
- 🧮 **Encrypted computation**: Perform calculations on encrypted values
- 🔑 **Key management**: Comprehensive key lifecycle management with audit logging
- 🧾 **Durable RAG retrieval**: PostgreSQL-backed encrypted document ingestion and keyword-token retrieval
- 💼 **Financial use cases**: Pre-built implementations for common financial-services scenarios
- ✅ **Well-tested**: Comprehensive test suite with >95% coverage

## Docker Compose Demo

Run the PostgreSQL-backed API workflow:

```bash
docker compose up --build
```

Open the API docs at <http://localhost:8000/docs>.

The Compose stack configures:

- `api`: FastAPI app using `uvicorn encrypted_ir.api.main:create_app --factory`
- `postgres`: durable PostgreSQL database for encrypted documents, keyword tokens, key metadata, and audit entries
- `DATABASE_URL`, `ENCRYPTED_IR_MASTER_KEY_B64`, `ENCRYPTED_IR_ENV`, `ENCRYPTED_IR_AUTO_CREATE_TABLES`, `ENCRYPTED_IR_CORS_ORIGINS`, and demo auth environment variables
- Alembic migrations run before the API starts

Example RAG-ready retrieval flow:

```bash
curl -X POST http://localhost:8000/v1/documents \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: local-demo-key' \
  -d '{"doc_id":"risk-001","content":"Quarterly fraud risk report for regulated RAG retrieval","metadata":{"source":"demo"}}'

curl -X POST http://localhost:8000/v1/rag/retrieve \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: local-demo-key' \
  -d '{"query":"fraud risk","top_k":3,"include_plaintext":true}'
```

The Compose stack enables `local-demo-key` through the dev-only auth path. Disable `ENCRYPTED_IR_DEV_AUTH_ENABLED` and configure real identity before treating the API as anything beyond a local demo.

See [docs/DOCKER_COMPOSE_SMOKE_TEST.md](docs/DOCKER_COMPOSE_SMOKE_TEST.md) for a restart-persistence smoke test.

## CTO Hardening Interfaces

Production-oriented configuration is intentionally stricter than the local demo:

- `ENCRYPTED_IR_ENV=dev|test|prod`
- `ENCRYPTED_IR_OIDC_ISSUER`
- `ENCRYPTED_IR_OIDC_AUDIENCE`
- `ENCRYPTED_IR_OIDC_JWKS_URL`
- `ENCRYPTED_IR_TENANT_CLAIM=tenant_id`
- `ENCRYPTED_IR_ROLES_CLAIM=roles`
- `ENCRYPTED_IR_KMS_PROVIDER=aws`
- `ENCRYPTED_IR_AWS_KMS_KEY_ID`
- `ENCRYPTED_IR_ENCRYPTED_MASTER_KEY_B64`

Useful commands:

```bash
python -m encrypted_ir.tools.generate_kms_master_key \
  --kms-key-id alias/encrypted-ir \
  --region us-east-1

alembic upgrade head

python -m encrypted_ir.tools.benchmark_retrieval \
  --database-url sqlite+pysqlite:///:memory: \
  --documents 1000 \
  --report benchmarks/reports/latest_retrieval.md
```

See [docs/PORTFOLIO_EVIDENCE.md](docs/PORTFOLIO_EVIDENCE.md),
[docs/LEAKAGE_AND_ENDPOINTS.md](docs/LEAKAGE_AND_ENDPOINTS.md), and
[docs/CTO_DEMO_SCRIPT.md](docs/CTO_DEMO_SCRIPT.md) for the security narrative.

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/encrypted-information-retrieval.git
cd encrypted-information-retrieval

# Install API/core dependencies
pip install -r requirements.txt

# Optional research demos: CKKS homomorphic encryption and post-quantum crypto
pip install -r requirements-research.txt

# Install the package
pip install -e .
```

## Quick Start

### 1. Deterministic Encryption (Account Numbers)

```python
from encrypted_ir import DeterministicEncryption

# Initialize encryptor
encryptor = DeterministicEncryption()

# Encrypt account numbers
account1 = "ACC-12345-6789"
encrypted1 = encryptor.encrypt_to_base64(account1)

# Same plaintext always produces same ciphertext (enables equality search)
encrypted2 = encryptor.encrypt_to_base64(account1)
assert encrypted1 == encrypted2

# Decrypt
decrypted = encryptor.decrypt_from_base64(encrypted1)
print(decrypted.decode('utf-8'))  # "ACC-12345-6789"
```

### 2. Searchable Encryption (Documents)

```python
from encrypted_ir import SearchableEncryption

# Initialize
encryptor = SearchableEncryption()

# Encrypt document with automatic keyword extraction
document = "Confidential financial report about quarterly earnings and fraud detection"
encrypted_doc, search_tokens = encryptor.encrypt_document(document)

# Search without decryption
query = encryptor.generate_search_query("fraud")
if encryptor.search(query, search_tokens):
    print("Document contains 'fraud'")

# Decrypt when needed
plaintext = encryptor.decrypt_document(encrypted_doc)
print(plaintext.decode('utf-8'))
```

### 3. Order-Preserving Encryption (Transaction Amounts)

```python
from encrypted_ir import OrderPreservingEncryption

# Initialize
encryptor = OrderPreservingEncryption()

# Encrypt transaction amounts
amounts = [100.00, 500.00, 1000.00, 5000.00]
encrypted_amounts = [encryptor.encrypt_amount(amt) for amt in amounts]

# Order is preserved - can do range queries!
threshold = encryptor.encrypt_amount(1000.00)
large_transactions = [enc for enc in encrypted_amounts if enc >= threshold]
print(f"Found {len(large_transactions)} transactions >= $1000")
```

### 4. Homomorphic Encryption (Credit Scoring)

```python
from encrypted_ir import BasicHomomorphicEncryption

# Initialize
encryptor = BasicHomomorphicEncryption()

# Encrypt financial data
income = encryptor.encrypt_value(75000.00)
debt = encryptor.encrypt_value(25000.00)

# Compute on encrypted data!
total = encryptor.add_encrypted(income, debt)
difference = encryptor.subtract_encrypted(income, debt)

# Decrypt results
print(f"Total: ${encryptor.decrypt_value(total):.2f}")
print(f"Net: ${encryptor.decrypt_value(difference):.2f}")
```

### 5. Key Management

```python
from encrypted_ir import KeyManager

# Initialize key manager
manager = KeyManager()

# Create encryption keys
det_key_id = manager.create_key(
    key_type="deterministic",
    rotation_period_days=90,
    description="Account number encryption"
)

# Retrieve key
key = manager.get_key(det_key_id)

# Check keys needing rotation
keys_to_rotate = manager.get_keys_needing_rotation()

# Rotate key
new_key_id = manager.rotate_key(det_key_id)

# Export keys securely
encrypted_bundle = manager.export_keys(password="secure_password")

# Audit trail
logs = manager.get_audit_log(limit=50)
```

## Financial Services Use Cases

### Account Management

```python
from encrypted_ir import KeyManager
from encrypted_ir.use_cases import AccountManagement

manager = KeyManager()
account_mgmt = AccountManagement(manager)

# Encrypt account numbers
accounts = ["ACC-001", "ACC-002", "ACC-003"]
encrypted_db = [account_mgmt.create_search_index(acc) for acc in accounts]

# Search for specific account
matches = account_mgmt.search_account("ACC-002", encrypted_db)
print(f"Account found at indices: {matches}")
```

### Transaction Processing

```python
from encrypted_ir import KeyManager
from encrypted_ir.use_cases import TransactionProcessing

manager = KeyManager()
processor = TransactionProcessing(manager)

# Encrypt transaction amounts
amounts = [50.00, 100.00, 500.00, 1000.00, 5000.00]
encrypted_amounts = [processor.encrypt_amount(amt) for amt in amounts]

# Find large transactions
large_txns = processor.find_large_transactions(encrypted_amounts, threshold=1000.00)
print(f"Found {len(large_txns)} large transactions")

# Range queries
in_range = processor.find_transactions_in_range(
    encrypted_amounts,
    min_amount=100.00,
    max_amount=1000.00
)
print(f"Found {len(in_range)} transactions in range")
```

### Document Search

```python
from encrypted_ir import KeyManager
from encrypted_ir.use_cases import DocumentSearch

manager = KeyManager()
doc_search = DocumentSearch(manager)

# Encrypt documents
doc_search.encrypt_document("doc_001", "Financial report about earnings")
doc_search.encrypt_document("doc_002", "Fraud detection analysis")

# Search across encrypted documents
matches = doc_search.search_documents("fraud")
print(f"Documents containing 'fraud': {matches}")

# Decrypt specific document
encrypted = doc_search.encrypt_document("doc_003", "Secret content")
decrypted = doc_search.decrypt_document(encrypted)
```

### Credit Scoring

```python
from encrypted_ir.use_cases import CreditScoring

scorer = CreditScoring()

# Encrypt customer financial data
encrypted_data = scorer.encrypt_financial_data(
    income=75000.00,
    debt=25000.00,
    credit_history_months=60
)

# Calculate credit score on encrypted data
score = scorer.calculate_credit_score(encrypted_data)
print(f"Credit Score: {score:.0f}")

# Calculate debt-to-income ratio
dti_ratio = scorer.calculate_debt_to_income_ratio(
    encrypted_data['income'],
    encrypted_data['debt']
)
print(f"DTI Ratio: {dti_ratio:.2%}")
```

### Fraud Detection

```python
from encrypted_ir import KeyManager
from encrypted_ir.use_cases import FraudDetection

manager = KeyManager()
fraud_detector = FraudDetection(manager)

# Encrypt transactions
transactions = [
    fraud_detector.encrypt_transaction("ACC-001", 100.00, "Store A"),
    fraud_detector.encrypt_transaction("ACC-001", 5000.00, "Store B"),
    fraud_detector.encrypt_transaction("ACC-002", 10000.00, "Store C"),
]

# Detect unusual amounts
suspicious = fraud_detector.detect_unusual_amounts(transactions, threshold=1000.00)
print(f"Suspicious transactions: {suspicious}")

# Detect rapid transactions
is_fraud = fraud_detector.detect_rapid_transactions(
    transactions,
    account_id="ACC-001",
    max_count=5
)
print(f"Fraud detected: {is_fraud}")
```

## Running Tests

```bash
# Install test dependencies
pip install pytest pytest-cov

# Run all tests
pytest

# Run with coverage
pytest --cov=encrypted_ir --cov-report=html

# Run specific test file
pytest tests/test_deterministic.py -v
```

## Security Considerations

### ⚠️ Important Security Notes

1. **Deterministic Encryption**: Same plaintext produces same ciphertext. Reveals equality patterns. Use only when equality search is essential.

2. **Order-Preserving Encryption**: Reveals ordering relationships. Use only when range queries are essential and the security trade-off is acceptable.

3. **Searchable Encryption**: May leak access patterns. Consider padding and obfuscation techniques for high-security environments.

4. **Homomorphic Encryption**: Most secure but slowest (100-1000x overhead). Use for sensitive computations where performance impact is acceptable.

5. **Key Management**:
   - Store master keys in Hardware Security Modules (HSMs) in production
   - Rotate keys regularly (default: 90 days)
   - Use strong passwords for key exports
   - Enable audit logging

### Best Practices

- ✅ Use deterministic encryption for indexed fields (account numbers, IDs)
- ✅ Use searchable encryption for text search (documents, emails)
- ✅ Use order-preserving encryption for numeric range queries (amounts, dates)
- ✅ Use homomorphic encryption for sensitive computations (credit scoring, analytics)
- ✅ Combine multiple techniques in a hybrid approach
- ✅ Implement proper key rotation policies
- ✅ Monitor and audit all encryption operations
- ✅ Test thoroughly before production deployment

## Performance Characteristics

Based on the analysis, here are typical performance characteristics:

| Encryption Type | Speed vs Plaintext | Use When |
|----------------|-------------------|----------|
| Deterministic | 2-5x slower | Need equality search |
| Searchable | 10-50x slower | Need keyword search |
| Order-Preserving | 5-30x slower | Need range queries |
| Homomorphic | 1000-10000x slower | Need encrypted computation |

## Architecture Recommendations

### For Financial Services

1. **Hybrid Approach**: Combine multiple encryption schemes
   - Account numbers: Deterministic
   - Transaction amounts: Order-preserving
   - Documents: Searchable
   - Analytics: Homomorphic

2. **Layered Security**:
   ```
   Layer 1: Deterministic encryption for indexed fields
   Layer 2: Searchable encryption for text fields
   Layer 3: Homomorphic encryption for calculations
   Layer 4: Traditional encryption for data at rest
   ```

3. **Key Management Strategy**:
   - Separate keys for different data types
   - Regular rotation (30-90 days)
   - Hardware-backed storage (HSMs)
   - Comprehensive audit trails

## Compliance

This prototype demonstrates technical controls that can support future
compliance work, but it is not certified or audit-ready by itself:

- **PCI DSS 4.0**: Cardholder data encryption
- **GDPR**: Data minimization and privacy by design
- **SOX**: Data integrity controls
- **DORA**: Operational resilience design inputs

## Roadmap

- [x] Post-quantum cryptography support (ML-KEM, ML-DSA)
- [ ] Hardware acceleration (GPU/FPGA support)
- [x] AWS KMS-wrapped app master key path
- [x] Advanced searchable encryption (conjunctive queries)
- [ ] Encrypted machine learning support
- [x] Format-preserving encryption (FF1, NIST SP 800-38G)
- [ ] REST API for encrypted search operations
- [ ] Forward privacy SSE (forward-secure searchable encryption)
- [ ] PIR mode (private information retrieval)

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) file for details.

## References

- [ANALYSIS.md](ANALYSIS.md) - Comprehensive analysis of encrypted IR for FS
- [Microsoft SEAL](https://github.com/microsoft/SEAL) - Homomorphic encryption library
- [TenSEAL](https://github.com/OpenMined/TenSEAL) - Tensor-based HE library
- NIST Special Publication 800-57: Key Management Recommendations
- PCI DSS v4.0: Payment Card Industry Data Security Standard

## Support

For issues and questions:
- Open an issue on GitHub
- Check existing documentation
- Review the analysis document

## Acknowledgments

This implementation is based on the comprehensive analysis of encrypted information retrieval for financial services, incorporating best practices from industry standards and academic research.
