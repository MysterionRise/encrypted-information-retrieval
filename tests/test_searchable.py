"""Tests for searchable encryption module."""

import pytest
from encrypted_ir.searchable import SearchableEncryption


class TestSearchableEncryption:
    """Test searchable encryption functionality."""

    def test_key_generation(self):
        """Test key generation."""
        enc_key, search_key = SearchableEncryption.generate_keys()
        assert len(enc_key) == 32
        assert len(search_key) == 32

    def test_document_encryption_decryption(self):
        """Test document encryption and decryption."""
        encryptor = SearchableEncryption()
        document = "This is a confidential financial report."

        encrypted_doc, tokens = encryptor.encrypt_document(document)
        decrypted = encryptor.decrypt_document(encrypted_doc)

        assert decrypted.decode("utf-8") == document
        assert len(tokens) > 0

    def test_keyword_extraction(self):
        """Test automatic keyword extraction."""
        encryptor = SearchableEncryption()
        document = "Financial transaction report for account analysis"

        _, tokens = encryptor.encrypt_document(document)

        # Should extract meaningful keywords (length > 2, not stop words)
        assert len(tokens) > 0

    def test_manual_keywords(self):
        """Test manual keyword specification."""
        encryptor = SearchableEncryption()
        document = "Document content"
        keywords = {"custom", "keywords", "test"}

        _, tokens = encryptor.encrypt_document(
            document, auto_extract_keywords=False, keywords=keywords
        )

        assert len(tokens) == len(keywords)

    def test_search_functionality(self):
        """Test search on encrypted documents."""
        encryptor = SearchableEncryption()
        document = "Financial report about transactions and fraud detection"

        encrypted_doc, doc_tokens = encryptor.encrypt_document(document)

        # Search for keyword that exists
        query1 = encryptor.generate_search_query("financial")
        assert encryptor.search(query1, doc_tokens) is True

        # Search for keyword that doesn't exist
        query2 = encryptor.generate_search_query("unicorn")
        assert encryptor.search(query2, doc_tokens) is False

    def test_case_insensitive_search(self):
        """Test that search is case-insensitive."""
        encryptor = SearchableEncryption()
        document = "Financial Report"

        _, doc_tokens = encryptor.encrypt_document(document)

        # Should find regardless of case
        query1 = encryptor.generate_search_query("financial")
        query2 = encryptor.generate_search_query("FINANCIAL")
        query3 = encryptor.generate_search_query("Financial")

        assert encryptor.search(query1, doc_tokens) is True
        assert encryptor.search(query2, doc_tokens) is True
        assert encryptor.search(query3, doc_tokens) is True

    def test_search_token_determinism(self):
        """Test that search tokens are deterministic."""
        encryptor = SearchableEncryption()

        token1 = encryptor.generate_search_query("test")
        token2 = encryptor.generate_search_query("test")

        assert token1 == token2

    def test_different_keywords_different_tokens(self):
        """Test that different keywords produce different tokens."""
        encryptor = SearchableEncryption()

        token1 = encryptor.generate_search_query("keyword1")
        token2 = encryptor.generate_search_query("keyword2")

        assert token1 != token2

    def test_base64_encoding(self):
        """Test base64 encoding/decoding."""
        encryptor = SearchableEncryption()
        document = "Test document"

        enc_doc_b64, tokens = encryptor.encrypt_document_to_base64(document)
        assert isinstance(enc_doc_b64, str)
        assert isinstance(tokens, list)

        decrypted = encryptor.decrypt_document_from_base64(enc_doc_b64)
        assert decrypted.decode("utf-8") == document

    def test_key_export_import(self):
        """Test key export and import."""
        encryptor1 = SearchableEncryption()
        document = "Test content"

        encrypted_doc, tokens = encryptor1.encrypt_document(document)

        # Export and import keys
        enc_key_b64, search_key_b64 = encryptor1.export_keys()
        encryptor2 = SearchableEncryption.import_keys(enc_key_b64, search_key_b64)

        # Should be able to decrypt and search with imported keys
        decrypted = encryptor2.decrypt_document(encrypted_doc)
        assert decrypted.decode("utf-8") == document

        query = encryptor2.generate_search_query("test")
        assert encryptor2.search(query, tokens) is True

    def test_invalid_key_size(self):
        """Test that invalid key size raises error."""
        with pytest.raises(ValueError):
            SearchableEncryption(encryption_key=b"short")

        with pytest.raises(ValueError):
            SearchableEncryption(encryption_key=b"0" * 32, search_key=b"short")

    def test_bytes_encryption(self):
        """Test encryption of binary data."""
        encryptor = SearchableEncryption()
        document = b"Binary content \x00\x01\x02"

        encrypted_doc, _ = encryptor.encrypt_document(document)
        decrypted = encryptor.decrypt_document(encrypted_doc)

        assert decrypted == document

    def test_decryption_with_wrong_key(self):
        """Test that decryption with wrong key fails."""
        encryptor1 = SearchableEncryption()
        encryptor2 = SearchableEncryption()

        document = "Secret content"
        encrypted_doc, _ = encryptor1.encrypt_document(document)

        # Decryption with wrong key should fail
        with pytest.raises(ValueError):
            encryptor2.decrypt_document(encrypted_doc)

    def test_multiple_documents(self):
        """Test searching across multiple documents."""
        encryptor = SearchableEncryption()

        docs = [
            "Financial report on quarterly earnings",
            "Transaction analysis and fraud detection",
            "Customer account management system",
        ]

        encrypted_docs = []
        for doc in docs:
            enc_doc, tokens = encryptor.encrypt_document(doc)
            encrypted_docs.append((enc_doc, tokens))

        # Search for "financial" - should match first doc
        query = encryptor.generate_search_query("financial")
        matches = [
            i for i, (_, tokens) in enumerate(encrypted_docs) if encryptor.search(query, tokens)
        ]
        assert matches == [0]

        # Search for "fraud" - should match second doc
        query = encryptor.generate_search_query("fraud")
        matches = [
            i for i, (_, tokens) in enumerate(encrypted_docs) if encryptor.search(query, tokens)
        ]
        assert matches == [1]
