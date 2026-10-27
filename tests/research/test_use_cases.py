"""Tests for financial services use cases."""

import pytest

from encrypted_ir.key_manager import KeyManager
from encrypted_ir.research.use_cases import (
    AccountManagement,
    CreditScoring,
    DocumentSearch,
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

    def setup_method(self):
        pytest.importorskip("tenseal")

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
