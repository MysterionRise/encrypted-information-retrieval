"""Tests for financial services use cases."""

import pytest
from encrypted_ir.key_manager import KeyManager
from encrypted_ir.use_cases import (
    AccountManagement,
    TransactionProcessing,
    DocumentSearch,
    CreditScoring,
    FraudDetection,
)


class TestAccountManagement:
    """Test account management use case."""

    def test_account_encryption(self):
        """Test account number encryption."""
        manager = KeyManager()
        account_mgmt = AccountManagement(manager)

        account_number = "ACC-12345-6789"
        encrypted = account_mgmt.encrypt_account_number(account_number)

        assert encrypted is not None
        assert encrypted != account_number

    def test_search_index_creation(self):
        """Test search index creation for accounts."""
        manager = KeyManager()
        account_mgmt = AccountManagement(manager)

        account_number = "ACC-99999-8888"
        index1 = account_mgmt.create_search_index(account_number)
        index2 = account_mgmt.create_search_index(account_number)

        # Same account should produce same index
        assert index1 == index2

    def test_account_search(self):
        """Test searching for account in encrypted database."""
        manager = KeyManager()
        account_mgmt = AccountManagement(manager)

        # Create encrypted account database
        accounts = ["ACC-001", "ACC-002", "ACC-003"]
        encrypted_accounts = [account_mgmt.create_search_index(acc) for acc in accounts]

        # Search for existing account
        matches = account_mgmt.search_account("ACC-002", encrypted_accounts)
        assert len(matches) == 1
        assert matches[0] == 1

        # Search for non-existent account
        matches = account_mgmt.search_account("ACC-999", encrypted_accounts)
        assert len(matches) == 0


class TestTransactionProcessing:
    """Test transaction processing use case."""

    def test_amount_encryption(self):
        """Test transaction amount encryption."""
        manager = KeyManager()
        txn_processor = TransactionProcessing(manager)

        amount = 1234.56
        encrypted = txn_processor.encrypt_amount(amount)

        assert encrypted > 0

    def test_find_large_transactions(self):
        """Test finding transactions above threshold."""
        manager = KeyManager()
        txn_processor = TransactionProcessing(manager)

        amounts = [100.00, 500.00, 1000.00, 5000.00, 10000.00]
        encrypted_amounts = [txn_processor.encrypt_amount(amt) for amt in amounts]

        # Find transactions over $1000
        large_txns = txn_processor.find_large_transactions(encrypted_amounts, 1000.00)

        # Should find 3 transactions >= $1000
        assert len(large_txns) == 3

    def test_range_query(self):
        """Test finding transactions in range."""
        manager = KeyManager()
        txn_processor = TransactionProcessing(manager)

        amounts = [50.00, 100.00, 500.00, 1000.00, 5000.00]
        encrypted_amounts = [txn_processor.encrypt_amount(amt) for amt in amounts]

        # Find transactions between $100 and $1000
        matches = txn_processor.find_transactions_in_range(encrypted_amounts, 100.00, 1000.00)

        # Should find $100, $500, $1000
        assert len(matches) == 3

    def test_order_preservation(self):
        """Test that encrypted amounts preserve order."""
        manager = KeyManager()
        txn_processor = TransactionProcessing(manager)

        amounts = [10.00, 20.00, 30.00, 40.00]
        encrypted = [txn_processor.encrypt_amount(amt) for amt in amounts]

        # Order should be preserved
        for i in range(len(encrypted) - 1):
            assert encrypted[i] < encrypted[i + 1]


class TestDocumentSearch:
    """Test document search use case."""

    def test_document_encryption(self):
        """Test document encryption."""
        manager = KeyManager()
        doc_search = DocumentSearch(manager)

        content = "This is a confidential financial report about quarterly earnings."
        encrypted = doc_search.encrypt_document("doc_001", content)

        assert encrypted is not None
        assert encrypted != content

    def test_document_decryption(self):
        """Test document decryption."""
        manager = KeyManager()
        doc_search = DocumentSearch(manager)

        content = "Confidential memo about merger negotiations."
        encrypted = doc_search.encrypt_document("doc_002", content)
        decrypted = doc_search.decrypt_document(encrypted)

        assert decrypted == content

    def test_keyword_search(self):
        """Test keyword search across documents."""
        manager = KeyManager()
        doc_search = DocumentSearch(manager)

        # Encrypt multiple documents
        doc_search.encrypt_document("doc_001", "Financial report about quarterly earnings")
        doc_search.encrypt_document("doc_002", "Transaction analysis and fraud detection")
        doc_search.encrypt_document("doc_003", "Customer account management procedures")

        # Search for "financial"
        matches = doc_search.search_documents("financial")
        assert "doc_001" in matches
        assert len(matches) == 1

        # Search for "fraud"
        matches = doc_search.search_documents("fraud")
        assert "doc_002" in matches

        # Search for "customer"
        matches = doc_search.search_documents("customer")
        assert "doc_003" in matches

    def test_search_no_matches(self):
        """Test search with no matches."""
        manager = KeyManager()
        doc_search = DocumentSearch(manager)

        doc_search.encrypt_document("doc_001", "Financial analysis report")

        # Search for word not in any document
        matches = doc_search.search_documents("blockchain")
        assert len(matches) == 0

    def test_multiple_keyword_matches(self):
        """Test document matching multiple keywords."""
        manager = KeyManager()
        doc_search = DocumentSearch(manager)

        doc_search.encrypt_document(
            "doc_001", "Analysis of transaction patterns for fraud detection"
        )

        # Both keywords should match the same document
        matches1 = doc_search.search_documents("transaction")
        matches2 = doc_search.search_documents("fraud")

        assert "doc_001" in matches1
        assert "doc_001" in matches2


class TestCreditScoring:
    """Test credit scoring use case."""

    def test_financial_data_encryption(self):
        """Test encryption of financial data."""
        scorer = CreditScoring()

        encrypted = scorer.encrypt_financial_data(
            income=75000.00, debt=25000.00, credit_history_months=60
        )

        assert "income" in encrypted
        assert "debt" in encrypted
        assert "credit_history" in encrypted

    def test_debt_to_income_ratio(self):
        """Test debt-to-income ratio calculation."""
        scorer = CreditScoring()

        encrypted = scorer.encrypt_financial_data(
            income=100000.00, debt=30000.00, credit_history_months=72
        )

        ratio = scorer.calculate_debt_to_income_ratio(encrypted["income"], encrypted["debt"])

        expected_ratio = 30000.00 / 100000.00
        assert abs(ratio - expected_ratio) < 0.01

    def test_credit_score_calculation(self):
        """Test credit score calculation."""
        scorer = CreditScoring()

        # Good credit profile
        encrypted = scorer.encrypt_financial_data(
            income=80000.00, debt=10000.00, credit_history_months=96
        )

        score = scorer.calculate_credit_score(encrypted)

        # Should be in valid range
        assert 300 <= score <= 850

        # Good profile should have decent score
        assert score > 500

    def test_credit_score_different_profiles(self):
        """Test that different profiles produce different scores."""
        scorer = CreditScoring()

        # Good profile
        good_profile = scorer.encrypt_financial_data(
            income=100000.00, debt=5000.00, credit_history_months=120
        )

        # Poor profile
        poor_profile = scorer.encrypt_financial_data(
            income=30000.00, debt=40000.00, credit_history_months=12
        )

        good_score = scorer.calculate_credit_score(good_profile)
        poor_score = scorer.calculate_credit_score(poor_profile)

        # Good profile should have higher score
        assert good_score > poor_score

    def test_zero_income_handling(self):
        """Test handling of zero income."""
        scorer = CreditScoring()

        encrypted = scorer.encrypt_financial_data(
            income=0.0, debt=1000.00, credit_history_months=12
        )

        ratio = scorer.calculate_debt_to_income_ratio(encrypted["income"], encrypted["debt"])

        # With HE, very small values might not be exactly 0, so check for very large ratio
        # The ratio might be inf or an extremely large number (positive or negative)
        assert ratio == float("inf") or abs(ratio) > 1000000


class TestFraudDetection:
    """Test fraud detection use case."""

    def test_transaction_encryption(self):
        """Test transaction data encryption."""
        manager = KeyManager()
        fraud_detector = FraudDetection(manager)

        encrypted = fraud_detector.encrypt_transaction(
            account_id="ACC-12345", amount=1500.00, merchant="Online Store XYZ"
        )

        assert "account_id" in encrypted
        assert "amount" in encrypted
        assert "merchant" in encrypted

    def test_unusual_amount_detection(self):
        """Test detection of unusual transaction amounts."""
        manager = KeyManager()
        fraud_detector = FraudDetection(manager)

        # Create transactions with various amounts
        transactions = [
            fraud_detector.encrypt_transaction("ACC-001", 50.00, "Store A"),
            fraud_detector.encrypt_transaction("ACC-002", 100.00, "Store B"),
            fraud_detector.encrypt_transaction("ACC-003", 5000.00, "Store C"),
            fraud_detector.encrypt_transaction("ACC-004", 10000.00, "Store D"),
        ]

        # Detect transactions over $1000
        suspicious = fraud_detector.detect_unusual_amounts(transactions, 1000.00)

        # Should detect last 2 transactions
        assert len(suspicious) == 2
        assert 2 in suspicious
        assert 3 in suspicious

    def test_rapid_transaction_detection(self):
        """Test detection of rapid transactions from same account."""
        manager = KeyManager()
        fraud_detector = FraudDetection(manager)

        account_id = "ACC-RAPID-001"

        # Create multiple transactions from same account
        transactions = [
            fraud_detector.encrypt_transaction(account_id, 100.00, f"Store {i}") for i in range(7)
        ]

        # Should detect fraud pattern (> 5 transactions)
        is_fraud = fraud_detector.detect_rapid_transactions(transactions, account_id, max_count=5)

        assert is_fraud is True

    def test_normal_transaction_pattern(self):
        """Test that normal patterns are not flagged."""
        manager = KeyManager()
        fraud_detector = FraudDetection(manager)

        account_id = "ACC-NORMAL-001"

        # Create normal number of transactions
        transactions = [
            fraud_detector.encrypt_transaction(account_id, 50.00, f"Store {i}") for i in range(3)
        ]

        # Should not detect fraud pattern
        is_fraud = fraud_detector.detect_rapid_transactions(transactions, account_id, max_count=5)

        assert is_fraud is False

    def test_mixed_account_transactions(self):
        """Test fraud detection with mixed accounts."""
        manager = KeyManager()
        fraud_detector = FraudDetection(manager)

        # Create transactions from different accounts
        transactions = [
            fraud_detector.encrypt_transaction("ACC-001", 100.00, "Store A"),
            fraud_detector.encrypt_transaction("ACC-002", 200.00, "Store B"),
            fraud_detector.encrypt_transaction("ACC-001", 150.00, "Store C"),
            fraud_detector.encrypt_transaction("ACC-003", 300.00, "Store D"),
        ]

        # Check rapid transactions for ACC-001 (2 transactions)
        is_fraud = fraud_detector.detect_rapid_transactions(transactions, "ACC-001", max_count=5)

        assert is_fraud is False
