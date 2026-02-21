"""
Financial Services Use Cases

Demonstrates practical applications of encrypted information retrieval
in financial services scenarios.
"""

from __future__ import annotations

from .deterministic import DeterministicEncryption
from .homomorphic import BasicHomomorphicEncryption
from .key_manager import KeyManager
from .order_preserving import OrderPreservingEncryption
from .searchable import SearchableEncryption


class AccountManagement:
    """
    Use case: Encrypted account number storage with equality search.

    Allows searching for accounts by encrypted account numbers without
    revealing the actual account numbers to the database.
    """

    def __init__(self, key_manager: KeyManager):
        self.key_manager = key_manager
        # Create encryption key for account numbers (64 bytes for AES-SIV)
        self.key_id = key_manager.create_key(
            "deterministic", key_size=64, description="Account number encryption"
        )
        key = key_manager.get_key(self.key_id)
        self.encryptor = DeterministicEncryption(key)

    def encrypt_account_number(self, account_number: str) -> str:
        """Encrypt an account number for storage."""
        return self.encryptor.encrypt_to_base64(account_number)

    def create_search_index(self, account_number: str) -> str:
        """Create searchable index for account number."""
        return self.encryptor.search_index(account_number)

    def search_account(self, account_number: str, encrypted_accounts: list[str]) -> list[int]:
        """
        Search for matching account in encrypted database.

        Args:
            account_number: Account number to search for
            encrypted_accounts: List of encrypted account numbers

        Returns:
            List of indices where account was found
        """
        search_token = self.create_search_index(account_number)
        matches = []
        for idx, enc_account in enumerate(encrypted_accounts):
            if enc_account == search_token:
                matches.append(idx)
        return matches


class TransactionProcessing:
    """
    Use case: Encrypted transaction amounts with range queries.

    Enables querying transactions by amount range while keeping
    actual amounts encrypted.
    """

    def __init__(self, key_manager: KeyManager):
        self.key_manager = key_manager
        self.key_id = key_manager.create_key("ope", description="Transaction amount encryption")
        key = key_manager.get_key(self.key_id)
        self.encryptor = OrderPreservingEncryption(key)

    def encrypt_amount(self, amount: float) -> int:
        """Encrypt a transaction amount."""
        return self.encryptor.encrypt_amount(amount)

    def find_large_transactions(self, encrypted_amounts: list[int], threshold: float) -> list[int]:
        """
        Find transactions above a threshold.

        Args:
            encrypted_amounts: List of encrypted transaction amounts
            threshold: Minimum amount threshold

        Returns:
            List of indices with amounts >= threshold
        """
        encrypted_threshold = self.encrypt_amount(threshold)
        return [
            idx for idx, enc_amt in enumerate(encrypted_amounts) if enc_amt >= encrypted_threshold
        ]

    def find_transactions_in_range(
        self, encrypted_amounts: list[int], min_amount: float, max_amount: float
    ) -> list[int]:
        """
        Find transactions within amount range.

        Args:
            encrypted_amounts: List of encrypted transaction amounts
            min_amount: Minimum amount
            max_amount: Maximum amount

        Returns:
            List of indices with amounts in range
        """
        enc_min = self.encrypt_amount(min_amount)
        enc_max = self.encrypt_amount(max_amount)

        return [
            idx for idx, enc_amt in enumerate(encrypted_amounts) if enc_min <= enc_amt <= enc_max
        ]


class DocumentSearch:
    """
    Use case: Searchable encrypted document management.

    Allows keyword search on encrypted financial documents
    (contracts, reports, emails) without exposing content.
    """

    def __init__(self, key_manager: KeyManager):
        self.key_manager = key_manager
        self.key_id = key_manager.create_key(
            "searchable", key_size=32, description="Document encryption"
        )
        enc_key = key_manager.get_key(self.key_id)

        # Create separate search key
        self.search_key_id = key_manager.create_key(
            "searchable_search", key_size=32, description="Document search tokens"
        )
        search_key = key_manager.get_key(self.search_key_id)

        self.encryptor = SearchableEncryption(enc_key, search_key)
        self.document_index: dict[str, set] = {}  # doc_id -> tokens

    def encrypt_document(self, doc_id: str, content: str) -> str:
        """
        Encrypt a document and build search index.

        Args:
            doc_id: Document identifier
            content: Document content

        Returns:
            Base64-encoded encrypted document
        """
        enc_doc, tokens = self.encryptor.encrypt_document_to_base64(content)
        self.document_index[doc_id] = set(tokens)
        return enc_doc

    def search_documents(self, keyword: str) -> list[str]:
        """
        Search for documents containing keyword.

        Args:
            keyword: Keyword to search for

        Returns:
            List of document IDs containing the keyword
        """
        query_token = self.encryptor.generate_search_query(keyword)
        matching_docs = []

        for doc_id, tokens in self.document_index.items():
            if self.encryptor.search(query_token, tokens):
                matching_docs.append(doc_id)

        return matching_docs

    def boolean_search_documents(self, keywords: list[str], operator: str = "AND") -> list[str]:
        """
        Search for documents using boolean (AND/OR) keyword queries.

        Args:
            keywords: List of keywords to search for
            operator: "AND" (all keywords must match) or "OR" (any keyword must match)

        Returns:
            List of document IDs matching the boolean query
        """
        query = self.encryptor.boolean_search_query(keywords, operator)
        matching_docs = []

        for doc_id, tokens in self.document_index.items():
            if self.encryptor.boolean_search(query, tokens):
                matching_docs.append(doc_id)

        return matching_docs

    def decrypt_document(self, encrypted_document: str) -> str:
        """
        Decrypt a document.

        Args:
            encrypted_document: Base64-encoded encrypted document

        Returns:
            Decrypted content
        """
        plaintext = self.encryptor.decrypt_document_from_base64(encrypted_document)
        return plaintext.decode("utf-8")


class CreditScoring:
    """
    Use case: Privacy-preserving credit scoring using homomorphic encryption.

    Computes credit scores on encrypted financial data using CKKS homomorphic
    arithmetic. Only the final score is decrypted — individual financial values
    (income, debt, credit history) remain encrypted throughout computation.

    Limitations:
        - CKKS does not support comparison (min/max), so normalization capping
          is applied to the final decrypted score rather than per-field.
        - CKKS does not support division, so debt-to-income ratio requires
          decrypting both operands. This is an inherent limitation of the
          CKKS scheme, not an implementation shortcut.
    """

    # Normalization constants (plaintext scalars applied to encrypted values)
    INCOME_CAP = 100000.0
    DEBT_CAP = 50000.0
    HISTORY_CAP = 120.0  # months (10 years)

    def __init__(self):
        self.encryptor = BasicHomomorphicEncryption()

    def encrypt_financial_data(
        self, income: float, debt: float, credit_history_months: int
    ) -> dict[str, str]:
        """
        Encrypt financial data for credit scoring.

        Args:
            income: Annual income
            debt: Total debt
            credit_history_months: Length of credit history in months

        Returns:
            Dictionary of encrypted values (as base64)
        """
        return {
            "income": self.encryptor.serialize_encrypted_to_base64(
                self.encryptor.encrypt_value(income)
            ),
            "debt": self.encryptor.serialize_encrypted_to_base64(
                self.encryptor.encrypt_value(debt)
            ),
            "credit_history": self.encryptor.serialize_encrypted_to_base64(
                self.encryptor.encrypt_value(credit_history_months)
            ),
        }

    def calculate_debt_to_income_ratio(
        self, encrypted_income_b64: str, encrypted_debt_b64: str
    ) -> float:
        """
        Calculate debt-to-income ratio.

        Note: CKKS does not natively support division. This operation requires
        decrypting both operands. This is an inherent limitation of the CKKS
        scheme — not an implementation shortcut. Polynomial approximation of
        1/x is possible but numerically unstable for the value ranges in
        financial data.

        Args:
            encrypted_income_b64: Encrypted income
            encrypted_debt_b64: Encrypted debt

        Returns:
            Debt-to-income ratio (decrypted)
        """
        enc_income = self.encryptor.deserialize_encrypted_from_base64(encrypted_income_b64)
        enc_debt = self.encryptor.deserialize_encrypted_from_base64(encrypted_debt_b64)

        income_val = self.encryptor.decrypt_value(enc_income)
        if income_val == 0:
            return float("inf")

        debt_val = self.encryptor.decrypt_value(enc_debt)
        return debt_val / income_val

    def calculate_credit_score(
        self, encrypted_data: dict[str, str], weights: dict[str, float] = None
    ) -> float:
        """
        Calculate weighted credit score using homomorphic operations.

        The computation is performed entirely on encrypted values:
        1. Each encrypted metric is multiplied by a plaintext scalar
           (weight / normalization_cap) using HE plaintext multiplication
        2. The weighted terms are summed using HE addition
        3. Only the final aggregate score is decrypted

        Individual financial values are never decrypted during scoring.
        Normalization capping (min with 1.0) cannot be done in CKKS, so
        it is applied to the final decrypted score via range clamping.

        Args:
            encrypted_data: Dictionary of encrypted financial metrics
            weights: Scoring weights (default if None)

        Returns:
            Credit score (300-850 scale)
        """
        if weights is None:
            weights = {
                "income": 0.3,
                "debt": -0.2,
                "credit_history": 0.5,
            }

        # Deserialize encrypted values
        enc_income = self.encryptor.deserialize_encrypted_from_base64(encrypted_data["income"])
        enc_debt = self.encryptor.deserialize_encrypted_from_base64(encrypted_data["debt"])
        enc_history = self.encryptor.deserialize_encrypted_from_base64(
            encrypted_data["credit_history"]
        )

        # HE plaintext multiplication: encrypted_value * (weight / cap)
        # This combines normalization and weighting into a single scalar multiply
        income_scalar = weights["income"] / self.INCOME_CAP
        debt_scalar = weights["debt"] / self.DEBT_CAP
        history_scalar = weights["credit_history"] / self.HISTORY_CAP

        weighted_income = self.encryptor.multiply_plain(enc_income, income_scalar)
        weighted_debt = self.encryptor.multiply_plain(enc_debt, debt_scalar)
        weighted_history = self.encryptor.multiply_plain(enc_history, history_scalar)

        # HE addition: sum all weighted encrypted terms
        raw_encrypted = self.encryptor.add_encrypted(weighted_income, weighted_debt)
        raw_encrypted = self.encryptor.add_encrypted(raw_encrypted, weighted_history)

        # Decrypt only the final aggregate score
        raw_score = self.encryptor.decrypt_value(raw_encrypted)

        # Scale to 300-850 range and clamp
        credit_score = 300 + (raw_score * 550)
        return max(300, min(850, credit_score))


class FraudDetection:
    """
    Use case: Encrypted fraud pattern detection.

    Detects suspicious transaction patterns while keeping
    transaction details encrypted.
    """

    def __init__(self, key_manager: KeyManager):
        self.key_manager = key_manager
        self.ope_key_id = key_manager.create_key(
            "ope_fraud", description="Transaction amount encryption for fraud detection"
        )
        ope_key = key_manager.get_key(self.ope_key_id)
        self.ope_encryptor = OrderPreservingEncryption(ope_key)

        self.det_key_id = key_manager.create_key(
            "deterministic_fraud",
            key_size=64,
            description="Account ID encryption for fraud detection",
        )
        det_key = key_manager.get_key(self.det_key_id)
        self.det_encryptor = DeterministicEncryption(det_key)

    def encrypt_transaction(self, account_id: str, amount: float, merchant: str) -> dict[str, any]:
        """
        Encrypt transaction data.

        Args:
            account_id: Account identifier
            amount: Transaction amount
            merchant: Merchant name

        Returns:
            Dictionary with encrypted fields
        """
        return {
            "account_id": self.det_encryptor.encrypt_to_base64(account_id),
            "amount": self.ope_encryptor.encrypt_amount(amount),
            "merchant": self.det_encryptor.encrypt_to_base64(merchant),
        }

    def detect_unusual_amounts(
        self, encrypted_transactions: list[dict], threshold_amount: float
    ) -> list[int]:
        """
        Detect transactions with unusual amounts.

        Args:
            encrypted_transactions: List of encrypted transactions
            threshold_amount: Suspicious amount threshold

        Returns:
            List of indices of suspicious transactions
        """
        enc_threshold = self.ope_encryptor.encrypt_amount(threshold_amount)
        suspicious = []

        for idx, txn in enumerate(encrypted_transactions):
            if txn["amount"] > enc_threshold:
                suspicious.append(idx)

        return suspicious

    def detect_rapid_transactions(
        self, encrypted_transactions: list[dict], account_id: str, max_count: int = 5
    ) -> bool:
        """
        Detect rapid succession of transactions from same account.

        Args:
            encrypted_transactions: List of encrypted transactions
            account_id: Account to check
            max_count: Maximum allowed transactions

        Returns:
            True if fraud pattern detected
        """
        enc_account = self.det_encryptor.encrypt_to_base64(account_id)
        count = sum(1 for txn in encrypted_transactions if txn["account_id"] == enc_account)
        return count > max_count
