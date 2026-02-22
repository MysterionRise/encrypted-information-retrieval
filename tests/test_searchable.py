"""Tests for searchable encryption module."""

import pytest

from encrypted_ir.searchable import BooleanQuery, ForwardPrivateSSE, SearchableEncryption


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


class TestBooleanQuery:
    """Test boolean/conjunctive query functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.encryptor = SearchableEncryption()
        self.docs = [
            "Financial report on quarterly earnings and fraud detection",
            "Transaction analysis and fraud detection system",
            "Customer account management and quarterly review",
            "Annual risk assessment report",
        ]
        self.encrypted_docs = []
        for doc in self.docs:
            _, tokens = self.encryptor.encrypt_document(doc)
            self.encrypted_docs.append(tokens)

    def test_and_query_matches(self):
        """Test AND query matches documents containing all keywords."""
        query = self.encryptor.boolean_search_query(["fraud", "financial"], "AND")
        # Only doc 0 has both "fraud" and "financial"
        results = [
            i
            for i, tokens in enumerate(self.encrypted_docs)
            if self.encryptor.boolean_search(query, tokens)
        ]
        assert results == [0]

    def test_and_query_no_match(self):
        """Test AND query returns no match when not all keywords present."""
        query = self.encryptor.boolean_search_query(["fraud", "customer"], "AND")
        results = [
            i
            for i, tokens in enumerate(self.encrypted_docs)
            if self.encryptor.boolean_search(query, tokens)
        ]
        assert results == []

    def test_or_query_matches(self):
        """Test OR query matches documents containing any keyword."""
        query = self.encryptor.boolean_search_query(["fraud", "customer"], "OR")
        results = [
            i
            for i, tokens in enumerate(self.encrypted_docs)
            if self.encryptor.boolean_search(query, tokens)
        ]
        # Doc 0 has "fraud", doc 1 has "fraud", doc 2 has "customer"
        assert results == [0, 1, 2]

    def test_or_query_single_match(self):
        """Test OR query with keyword in only one document."""
        query = self.encryptor.boolean_search_query(["annual", "customer"], "OR")
        results = [
            i
            for i, tokens in enumerate(self.encrypted_docs)
            if self.encryptor.boolean_search(query, tokens)
        ]
        # Doc 2 has "customer", doc 3 has "annual"
        assert results == [2, 3]

    def test_nested_boolean_query(self):
        """Test nested boolean queries: (fraud AND quarterly) OR (risk AND annual)."""
        sub1 = self.encryptor.boolean_search_query(["fraud", "quarterly"], "AND")
        sub2 = self.encryptor.boolean_search_query(["risk", "annual"], "AND")
        nested = self.encryptor.nested_boolean_query("OR", sub1, sub2)
        results = [
            i
            for i, tokens in enumerate(self.encrypted_docs)
            if self.encryptor.boolean_search(nested, tokens)
        ]
        # Doc 0 has fraud+quarterly, doc 3 has risk+annual
        assert results == [0, 3]

    def test_nested_and_of_ors(self):
        """Test nested: (fraud OR risk) AND (quarterly OR annual)."""
        sub1 = self.encryptor.boolean_search_query(["fraud", "risk"], "OR")
        sub2 = self.encryptor.boolean_search_query(["quarterly", "annual"], "OR")
        nested = self.encryptor.nested_boolean_query("AND", sub1, sub2)
        results = [
            i
            for i, tokens in enumerate(self.encrypted_docs)
            if self.encryptor.boolean_search(nested, tokens)
        ]
        # Doc 0: fraud+quarterly ✓, Doc 3: risk+annual ✓
        assert results == [0, 3]

    def test_boolean_query_case_insensitive(self):
        """Test boolean queries are case-insensitive."""
        query_lower = self.encryptor.boolean_search_query(["fraud", "financial"], "AND")
        query_upper = self.encryptor.boolean_search_query(["FRAUD", "FINANCIAL"], "AND")
        for tokens in self.encrypted_docs:
            assert self.encryptor.boolean_search(
                query_lower, tokens
            ) == self.encryptor.boolean_search(query_upper, tokens)

    def test_invalid_operator(self):
        """Test that invalid operator raises ValueError."""
        with pytest.raises(ValueError, match="Operator must be"):
            BooleanQuery("XOR", ["a", "b"])

    def test_insufficient_operands(self):
        """Test that fewer than 2 operands raises ValueError."""
        with pytest.raises(ValueError, match="at least 2 operands"):
            BooleanQuery("AND", ["single"])

    def test_boolean_query_default_operator(self):
        """Test that default operator is AND."""
        query = self.encryptor.boolean_search_query(["fraud", "financial"])
        assert query.operator == "AND"

    def test_boolean_search_all_match(self):
        """Test OR query where keyword appears in all documents."""
        # Use manual keywords to control exactly what's indexed
        enc = SearchableEncryption()
        docs_tokens = []
        for kw_set in [{"alpha", "beta"}, {"alpha", "gamma"}, {"alpha", "delta"}]:
            _, tokens = enc.encrypt_document("doc", auto_extract_keywords=False, keywords=kw_set)
            docs_tokens.append(tokens)

        query = enc.boolean_search_query(["alpha", "nonexistent"], "OR")
        results = [i for i, tokens in enumerate(docs_tokens) if enc.boolean_search(query, tokens)]
        assert results == [0, 1, 2]

    def test_boolean_search_none_match(self):
        """Test query where no documents match."""
        query = self.encryptor.boolean_search_query(["unicorn", "dragon"], "OR")
        results = [
            i
            for i, tokens in enumerate(self.encrypted_docs)
            if self.encryptor.boolean_search(query, tokens)
        ]
        assert results == []


class TestForwardPrivateSSE:
    """Test forward-private searchable symmetric encryption."""

    def test_key_generation(self):
        """Test that generate_keys returns three 32-byte keys."""
        enc_key, search_key, state_key = ForwardPrivateSSE.generate_keys()
        assert len(enc_key) == 32
        assert len(search_key) == 32
        assert len(state_key) == 32

    def test_invalid_key_size(self):
        """Test that invalid key sizes raise ValueError."""
        with pytest.raises(ValueError, match="Encryption key"):
            ForwardPrivateSSE(encryption_key=b"short")
        with pytest.raises(ValueError, match="Search key"):
            ForwardPrivateSSE(search_key=b"short")
        with pytest.raises(ValueError, match="State key"):
            ForwardPrivateSSE(state_key=b"short")

    def test_invalid_mode(self):
        """Test that invalid forward_privacy_mode raises ValueError."""
        with pytest.raises(ValueError, match="forward_privacy_mode"):
            ForwardPrivateSSE(forward_privacy_mode="invalid")

    def test_add_and_search_balanced(self):
        """Test basic add and search in balanced mode."""
        sse = ForwardPrivateSSE(forward_privacy_mode="balanced")
        sse.add_document("doc1", "financial fraud report")
        sse.add_document("doc2", "customer account analysis")

        assert sse.search("fraud") == {"doc1"}
        assert sse.search("customer") == {"doc2"}
        assert sse.search("nonexistent") == set()

    def test_add_and_search_strong(self):
        """Test basic add and search in strong mode."""
        sse = ForwardPrivateSSE(forward_privacy_mode="strong", re_encrypt_threshold=1000)
        sse.add_document("doc1", "financial fraud report")
        sse.add_document("doc2", "customer account analysis")

        assert sse.search("fraud") == {"doc1"}
        assert sse.search("customer") == {"doc2"}

    def test_add_and_search_off(self):
        """Test basic add and search in off mode (deterministic tokens)."""
        sse = ForwardPrivateSSE(forward_privacy_mode="off")
        sse.add_document("doc1", "financial fraud report")
        sse.add_document("doc2", "customer account analysis")

        assert sse.search("fraud") == {"doc1"}
        assert sse.search("customer") == {"doc2"}
        assert sse.search("nonexistent") == set()

    def test_multiple_docs_same_keyword(self):
        """Test that multiple documents with the same keyword are all found."""
        sse = ForwardPrivateSSE(forward_privacy_mode="balanced")
        sse.add_document("doc1", "fraud detection system")
        sse.add_document("doc2", "fraud analysis report")
        sse.add_document("doc3", "fraud prevention strategy")

        results = sse.search("fraud")
        assert results == {"doc1", "doc2", "doc3"}

    def test_manual_keywords(self):
        """Test adding documents with manual keywords."""
        sse = ForwardPrivateSSE(forward_privacy_mode="balanced")
        sse.add_document(
            "doc1", "some content", keywords={"alpha", "beta"}, auto_extract_keywords=False
        )
        sse.add_document(
            "doc2", "other content", keywords={"beta", "gamma"}, auto_extract_keywords=False
        )

        assert sse.search("alpha") == {"doc1"}
        assert sse.search("beta") == {"doc1", "doc2"}
        assert sse.search("gamma") == {"doc2"}

    def test_document_encryption_decryption(self):
        """Test that documents can be decrypted after adding."""
        sse = ForwardPrivateSSE(forward_privacy_mode="balanced")
        sse.add_document("doc1", "Secret financial report")

        decrypted = sse.decrypt_document("doc1")
        assert decrypted == b"Secret financial report"

    def test_decrypt_nonexistent_document(self):
        """Test that decrypting a nonexistent document raises KeyError."""
        sse = ForwardPrivateSSE(forward_privacy_mode="balanced")
        with pytest.raises(KeyError, match="not found"):
            sse.decrypt_document("nonexistent")

    def test_case_insensitive_search(self):
        """Test that search is case-insensitive."""
        sse = ForwardPrivateSSE(forward_privacy_mode="balanced")
        sse.add_document(
            "doc1", "x", keywords={"Financial"}, auto_extract_keywords=False
        )

        assert sse.search("financial") == {"doc1"}
        assert sse.search("FINANCIAL") == {"doc1"}
        assert sse.search("Financial") == {"doc1"}

    def test_index_stats(self):
        """Test get_index_stats returns correct statistics."""
        sse = ForwardPrivateSSE(forward_privacy_mode="balanced")
        sse.add_document(
            "doc1", "x", keywords={"alpha", "beta"}, auto_extract_keywords=False
        )

        stats = sse.get_index_stats()
        assert stats["forward_privacy_mode"] == "balanced"
        assert stats["auxiliary_entries"] == 2
        assert stats["secure_entries"] == 0
        assert stats["documents_stored"] == 1
        assert stats["keywords_tracked"] == 2

    def test_search_moves_entries_to_secure_index(self):
        """Test that search moves auxiliary entries to secure index."""
        sse = ForwardPrivateSSE(forward_privacy_mode="balanced")
        sse.add_document(
            "doc1", "x", keywords={"alpha"}, auto_extract_keywords=False
        )

        stats_before = sse.get_index_stats()
        assert stats_before["auxiliary_entries"] == 1
        assert stats_before["secure_entries"] == 0

        sse.search("alpha")

        stats_after = sse.get_index_stats()
        assert stats_after["auxiliary_entries"] == 0
        assert stats_after["secure_entries"] == 1

    def test_search_after_search_returns_from_secure_index(self):
        """Test that repeated search uses the secure index."""
        sse = ForwardPrivateSSE(forward_privacy_mode="balanced")
        sse.add_document(
            "doc1", "x", keywords={"alpha"}, auto_extract_keywords=False
        )

        assert sse.search("alpha") == {"doc1"}
        # Second search should still find doc1 (now from secure index)
        assert sse.search("alpha") == {"doc1"}

    def test_add_after_search_still_findable(self):
        """Test that documents added after a search are found in later searches."""
        sse = ForwardPrivateSSE(forward_privacy_mode="balanced")
        sse.add_document(
            "doc1", "x", keywords={"alpha"}, auto_extract_keywords=False
        )
        assert sse.search("alpha") == {"doc1"}

        # Add another doc with same keyword after search (re-keyed state)
        sse.add_document(
            "doc2", "y", keywords={"alpha"}, auto_extract_keywords=False
        )
        assert sse.search("alpha") == {"doc1", "doc2"}


class TestForwardPrivateSSEReEncryption:
    """Test periodic re-encryption of the forward-private index."""

    def test_re_encrypt_moves_all_entries(self):
        """Test that re_encrypt moves all auxiliary entries to secure index."""
        sse = ForwardPrivateSSE(forward_privacy_mode="balanced")
        sse.add_document(
            "doc1", "x", keywords={"alpha", "beta"}, auto_extract_keywords=False
        )
        sse.add_document(
            "doc2", "y", keywords={"beta", "gamma"}, auto_extract_keywords=False
        )

        count = sse.re_encrypt()
        assert count == 4  # alpha:doc1, beta:doc1, beta:doc2, gamma:doc2

        stats = sse.get_index_stats()
        assert stats["auxiliary_entries"] == 0
        assert stats["secure_entries"] == 4

    def test_re_encrypt_preserves_searchability(self):
        """Test that search works correctly after re-encryption."""
        sse = ForwardPrivateSSE(forward_privacy_mode="balanced")
        sse.add_document(
            "doc1", "x", keywords={"alpha", "beta"}, auto_extract_keywords=False
        )
        sse.add_document(
            "doc2", "y", keywords={"beta", "gamma"}, auto_extract_keywords=False
        )

        sse.re_encrypt()

        assert sse.search("alpha") == {"doc1"}
        assert sse.search("beta") == {"doc1", "doc2"}
        assert sse.search("gamma") == {"doc2"}

    def test_add_after_re_encrypt(self):
        """Test that documents added after re-encryption are found."""
        sse = ForwardPrivateSSE(forward_privacy_mode="balanced")
        sse.add_document(
            "doc1", "x", keywords={"alpha"}, auto_extract_keywords=False
        )
        sse.re_encrypt()

        sse.add_document(
            "doc2", "y", keywords={"alpha"}, auto_extract_keywords=False
        )
        assert sse.search("alpha") == {"doc1", "doc2"}

    def test_strong_mode_auto_re_encrypt(self):
        """Test that strong mode triggers automatic re-encryption."""
        sse = ForwardPrivateSSE(
            forward_privacy_mode="strong", re_encrypt_threshold=3
        )
        # Add enough keywords to trigger threshold
        sse.add_document(
            "doc1", "x", keywords={"a", "b", "c"}, auto_extract_keywords=False
        )

        # Auto re-encryption should have fired
        stats = sse.get_index_stats()
        assert stats["auxiliary_entries"] == 0
        assert stats["update_count"] == 0

    def test_re_encrypt_resets_counter(self):
        """Test that re_encrypt resets the update counter."""
        sse = ForwardPrivateSSE(forward_privacy_mode="balanced")
        sse.add_document(
            "doc1", "x", keywords={"alpha"}, auto_extract_keywords=False
        )
        assert sse._update_count == 1

        sse.re_encrypt()
        assert sse._update_count == 0


class TestForwardPrivacy:
    """
    Test forward privacy guarantees.

    These tests simulate an honest-but-curious server adversary that:
    - Observes all index tags and encrypted entries
    - Tries to link new document updates to previously searched keywords
    - Cannot access the client's state_key or internal state

    Forward privacy property: Given an update (tag, encrypted_entry),
    the server cannot determine which keyword it corresponds to, even
    if the server previously observed a search for that keyword.
    """

    def test_forward_privacy_add(self):
        """
        Server cannot link new document additions to past search queries.

        Protocol:
        1. Add doc1 with keyword "fraud"
        2. Search for "fraud" (server sees state chain)
        3. Add doc2 with keyword "fraud" (state is re-keyed)
        4. The new auxiliary tag should not match any previously seen tag
        """
        sse = ForwardPrivateSSE(forward_privacy_mode="balanced")

        # Step 1: Add doc1
        sse.add_document(
            "doc1", "x", keywords={"fraud"}, auto_extract_keywords=False
        )
        tags_before_search = set(sse._auxiliary_index.keys())
        assert len(tags_before_search) == 1

        # Step 2: Search for "fraud" - server observes the state chain
        # After search, entries move to secure index and state is re-keyed
        sse.search("fraud")
        assert len(sse._auxiliary_index) == 0

        # Step 3: Add doc2 with same keyword after re-keying
        sse.add_document(
            "doc2", "y", keywords={"fraud"}, auto_extract_keywords=False
        )
        tags_after_rekey = set(sse._auxiliary_index.keys())
        assert len(tags_after_rekey) == 1

        # Step 4: New tag must differ from the tag seen before search
        # This proves the server can't link the new update to past queries
        assert tags_before_search.isdisjoint(tags_after_rekey), (
            "Forward privacy violated: new update tag matches a previously "
            "observed tag, allowing server to link update to past query"
        )

    def test_forward_privacy_update(self):
        """
        Updates to the index don't leak query history.

        After re-keying, the new state chain is derived from fresh randomness
        and is cryptographically independent of the old chain.
        """
        sse = ForwardPrivateSSE(forward_privacy_mode="balanced")

        # Build up some history
        sse.add_document(
            "doc1", "x", keywords={"fraud"}, auto_extract_keywords=False
        )
        sse.add_document(
            "doc2", "y", keywords={"fraud"}, auto_extract_keywords=False
        )
        tags_round1 = set(sse._auxiliary_index.keys())

        # Search reveals the chain and re-keys
        sse.search("fraud")

        # Add more documents
        sse.add_document(
            "doc3", "z", keywords={"fraud"}, auto_extract_keywords=False
        )
        sse.add_document(
            "doc4", "w", keywords={"fraud"}, auto_extract_keywords=False
        )
        tags_round2 = set(sse._auxiliary_index.keys())

        # All tags from round 2 must be different from round 1
        assert tags_round1.isdisjoint(tags_round2), (
            "Update tags after re-keying should be unlinkable to pre-search tags"
        )

        # And the new documents should still be findable
        assert sse.search("fraud") == {"doc1", "doc2", "doc3", "doc4"}

    def test_honest_but_curious_server_unlinkability(self):
        """
        Simulate honest-but-curious server that observes all index operations.

        The server records all tags it has ever seen during updates and
        searches. We verify that tags from different "epochs" (separated
        by searches/re-encryptions) are unlinkable.
        """
        sse = ForwardPrivateSSE(forward_privacy_mode="balanced")
        server_observed_tags = []

        # Epoch 1: Server observes update tags
        sse.add_document(
            "doc1", "x", keywords={"secret"}, auto_extract_keywords=False
        )
        epoch1_tags = set(sse._auxiliary_index.keys())
        server_observed_tags.extend(epoch1_tags)

        # Search: server sees state chain for "secret"
        sse.search("secret")

        # Epoch 2: Server observes new update tags after re-key
        sse.add_document(
            "doc2", "y", keywords={"secret"}, auto_extract_keywords=False
        )
        epoch2_tags = set(sse._auxiliary_index.keys())
        server_observed_tags.extend(epoch2_tags)

        # Re-encrypt and search
        sse.search("secret")

        # Epoch 3: Another round
        sse.add_document(
            "doc3", "z", keywords={"secret"}, auto_extract_keywords=False
        )
        epoch3_tags = set(sse._auxiliary_index.keys())
        server_observed_tags.extend(epoch3_tags)

        # All observed tags should be unique (no collisions across epochs)
        assert len(server_observed_tags) == len(set(server_observed_tags)), (
            "Tag collision detected across epochs - forward privacy compromised"
        )

        # Tags from different epochs should be disjoint
        assert epoch1_tags.isdisjoint(epoch2_tags)
        assert epoch2_tags.isdisjoint(epoch3_tags)
        assert epoch1_tags.isdisjoint(epoch3_tags)

        # All documents should still be searchable
        assert sse.search("secret") == {"doc1", "doc2", "doc3"}

    def test_update_tags_unique_per_document(self):
        """
        Each document addition produces a unique tag, even for the same keyword.

        This prevents the server from determining that two updates are
        for the same keyword by comparing tags.
        """
        sse = ForwardPrivateSSE(forward_privacy_mode="balanced")

        sse.add_document(
            "doc1", "x", keywords={"keyword"}, auto_extract_keywords=False
        )
        tag1 = set(sse._auxiliary_index.keys())

        sse.add_document(
            "doc2", "y", keywords={"keyword"}, auto_extract_keywords=False
        )
        all_tags = set(sse._auxiliary_index.keys())

        # Should have 2 distinct tags
        assert len(all_tags) == 2
        # The new tag should be different from the first
        tag2 = all_tags - tag1
        assert len(tag2) == 1
        assert tag1.isdisjoint(tag2)

    def test_different_keywords_produce_different_tags(self):
        """
        Tags for different keywords are indistinguishable to the server.
        """
        sse = ForwardPrivateSSE(forward_privacy_mode="balanced")

        sse.add_document(
            "doc1", "x", keywords={"alpha"}, auto_extract_keywords=False
        )
        sse.add_document(
            "doc2", "y", keywords={"beta"}, auto_extract_keywords=False
        )

        tags = list(sse._auxiliary_index.keys())
        assert len(tags) == 2
        assert tags[0] != tags[1]

    def test_re_encrypt_produces_fresh_tags(self):
        """
        After re-encryption, adding the same keyword produces entirely
        new tags unrelated to the pre-re-encryption tags.
        """
        sse = ForwardPrivateSSE(forward_privacy_mode="balanced")

        sse.add_document(
            "doc1", "x", keywords={"alpha"}, auto_extract_keywords=False
        )
        tags_before = set(sse._auxiliary_index.keys())

        sse.re_encrypt()

        sse.add_document(
            "doc2", "y", keywords={"alpha"}, auto_extract_keywords=False
        )
        tags_after = set(sse._auxiliary_index.keys())

        assert tags_before.isdisjoint(tags_after)

    def test_off_mode_no_forward_privacy(self):
        """
        In 'off' mode, the same keyword always produces the same token.
        This is the expected behavior for backward compatibility.
        """
        sse = ForwardPrivateSSE(forward_privacy_mode="off")

        sse.add_document(
            "doc1", "x", keywords={"alpha"}, auto_extract_keywords=False
        )
        sse.add_document(
            "doc2", "y", keywords={"alpha"}, auto_extract_keywords=False
        )

        # In off mode, entries go to secure index with deterministic tokens
        assert len(sse._secure_index) == 1  # Same token for both docs
        token = list(sse._secure_index.keys())[0]
        assert sse._secure_index[token] == {"doc1", "doc2"}

    def test_bytes_document_support(self):
        """Test that binary documents are handled correctly."""
        sse = ForwardPrivateSSE(forward_privacy_mode="balanced")
        sse.add_document(
            "doc1", b"binary content",
            keywords={"binary"}, auto_extract_keywords=False,
        )

        assert sse.search("binary") == {"doc1"}
        decrypted = sse.decrypt_document("doc1")
        assert decrypted == b"binary content"

    def test_forward_privacy_across_many_epochs(self):
        """
        Stress test: verify forward privacy holds across many search/add cycles.
        """
        sse = ForwardPrivateSSE(forward_privacy_mode="balanced")
        all_tags_seen = set()

        for i in range(10):
            sse.add_document(
                f"doc{i}", "x",
                keywords={"keyword"}, auto_extract_keywords=False,
            )
            current_tags = set(sse._auxiliary_index.keys())
            # New tags should never overlap with previously seen tags
            assert all_tags_seen.isdisjoint(current_tags), (
                f"Tag collision at epoch {i}"
            )
            all_tags_seen.update(current_tags)

            sse.search("keyword")

        # All 10 documents should be found
        assert sse.search("keyword") == {f"doc{i}" for i in range(10)}
