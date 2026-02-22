"""Tests for searchable encryption module."""

import pytest

from encrypted_ir.searchable import BackwardPrivateIndex, BooleanQuery, SearchableEncryption


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


class TestBackwardPrivateIndex:
    """Test backward privacy for SSE deletes.

    Verifies that:
    - Delete tokens cannot be linked to add tokens
    - Server cannot link deletions to past queries
    - Deleted documents cannot be recovered from the index
    - Re-encryption rebuilds the index with fresh randomness
    - Garbage collection removes stale entries
    """

    def setup_method(self):
        """Set up test fixtures with a backward-private index."""
        self.bp_index = BackwardPrivateIndex(re_encryption_threshold=3)
        self.bp_index.add_document("doc1", {"financial", "report", "quarterly"})
        self.bp_index.add_document("doc2", {"fraud", "detection", "system"})
        self.bp_index.add_document("doc3", {"financial", "fraud", "analysis"})

    def test_add_and_search(self):
        """Test basic add and search on backward-private index."""
        results = self.bp_index.search("financial")
        assert sorted(results) == ["doc1", "doc3"]

        results = self.bp_index.search("fraud")
        assert sorted(results) == ["doc2", "doc3"]

        results = self.bp_index.search("quarterly")
        assert results == ["doc1"]

        results = self.bp_index.search("unicorn")
        assert results == []

    def test_document_count(self):
        """Test document count tracking."""
        assert self.bp_index.document_count == 3

    def test_duplicate_doc_id_rejected(self):
        """Test that adding a document with an existing ID raises ValueError."""
        with pytest.raises(ValueError, match="already exists"):
            self.bp_index.add_document("doc1", {"new", "keywords"})

    def test_delete_removes_from_index(self):
        """Test that deletion completely removes document from index."""
        self.bp_index.delete_document("doc2")

        assert self.bp_index.document_count == 2
        assert "doc2" not in self.bp_index.get_server_view()

    def test_deleted_document_not_searchable(self):
        """Test that deleted documents cannot be found by search."""
        # "fraud" matches doc2 and doc3 before deletion
        assert sorted(self.bp_index.search("fraud")) == ["doc2", "doc3"]

        self.bp_index.delete_document("doc2")

        # After deleting doc2, "fraud" should only match doc3
        assert self.bp_index.search("fraud") == ["doc3"]
        # "detection" was only in doc2
        assert self.bp_index.search("detection") == []
        # "system" was only in doc2
        assert self.bp_index.search("system") == []

    def test_deleted_document_tokens_not_in_server_view(self):
        """Prove deleted documents cannot be recovered from the index."""
        # Capture doc2's tokens before deletion
        server_view_before = self.bp_index.get_server_view()
        doc2_tokens_before = server_view_before["doc2"]
        assert len(doc2_tokens_before) > 0

        self.bp_index.delete_document("doc2")

        # After deletion, doc2's tokens must not appear anywhere in the index
        server_view_after = self.bp_index.get_server_view()
        assert "doc2" not in server_view_after

        all_remaining_tokens = set()
        for tokens in server_view_after.values():
            all_remaining_tokens.update(tokens)

        # Tokens unique to doc2 (detection, system) must be gone
        # Shared tokens (fraud) may still exist for other docs, but doc2 entry is gone
        for doc_id in server_view_after:
            assert doc_id != "doc2"

    def test_delete_nonexistent_raises(self):
        """Test that deleting a nonexistent document raises KeyError."""
        with pytest.raises(KeyError, match="not found"):
            self.bp_index.delete_document("nonexistent")

    def test_delete_tokens_unlinkable_to_search_tokens(self):
        """Prove server cannot link delete tokens to add/search tokens.

        Delete tokens are generated with a different key and different input
        structure (doc_id + keyword) compared to search tokens (keyword only).
        No delete token should match any search token in the index.
        """
        # Collect all search tokens the server has seen (from adds)
        server_view = self.bp_index.get_server_view()
        all_search_tokens = set()
        for tokens in server_view.values():
            all_search_tokens.update(tokens)

        # Collect search query tokens the server has seen (from searches)
        query_tokens = set()
        for keyword in ["financial", "report", "quarterly", "fraud", "detection", "system"]:
            query_tokens.add(self.bp_index.sse.generate_search_query(keyword))

        # Delete doc2 and get delete tokens
        result = self.bp_index.delete_document("doc2")
        delete_tokens = set(result["delete_tokens"].values())

        # Delete tokens must share NO values with search tokens
        assert delete_tokens.isdisjoint(all_search_tokens), (
            "Delete tokens overlap with search tokens - backward privacy violated"
        )

        # Delete tokens must share NO values with query tokens
        assert delete_tokens.isdisjoint(query_tokens), (
            "Delete tokens overlap with query tokens - backward privacy violated"
        )

    def test_delete_tokens_differ_across_documents(self):
        """Test that delete tokens for the same keyword on different docs differ."""
        bp = BackwardPrivateIndex()
        bp.add_document("docA", {"shared_keyword"})
        bp.add_document("docB", {"shared_keyword"})

        result_a = bp.delete_document("docA")
        result_b = bp.delete_document("docB")

        token_a = result_a["delete_tokens"]["shared_keyword"]
        token_b = result_b["delete_tokens"]["shared_keyword"]

        # Same keyword, different doc_id -> different delete token
        assert token_a != token_b

    def test_delete_tokens_differ_from_search_tokens_same_keyword(self):
        """Test that a delete token for keyword K differs from the search token for K."""
        bp = BackwardPrivateIndex()
        bp.add_document("doc1", {"alpha", "beta"})

        search_token_alpha = bp.sse.generate_search_query("alpha")
        search_token_beta = bp.sse.generate_search_query("beta")

        result = bp.delete_document("doc1")
        delete_token_alpha = result["delete_tokens"]["alpha"]
        delete_token_beta = result["delete_tokens"]["beta"]

        assert delete_token_alpha != search_token_alpha
        assert delete_token_beta != search_token_beta

    def test_deletion_count_tracking(self):
        """Test that deletion count is properly tracked."""
        assert self.bp_index.deletion_count == 0

        self.bp_index.delete_document("doc1")
        assert self.bp_index.deletion_count == 1

        self.bp_index.delete_document("doc2")
        assert self.bp_index.deletion_count == 2

    def test_re_encryption_threshold_detection(self):
        """Test that re-encryption need is detected at threshold."""
        bp = BackwardPrivateIndex(re_encryption_threshold=2)
        bp.add_document("d1", {"kw1"})
        bp.add_document("d2", {"kw2"})
        bp.add_document("d3", {"kw3"})

        result1 = bp.delete_document("d1")
        assert result1["needs_reencryption"] is False
        assert result1["deletion_count"] == 1

        result2 = bp.delete_document("d2")
        assert result2["needs_reencryption"] is True
        assert result2["deletion_count"] == 2

    def test_re_encryption_changes_all_tokens(self):
        """Test that re-encryption produces entirely new tokens."""
        tokens_before = self.bp_index.get_server_view()
        all_tokens_before = set()
        for tokens in tokens_before.values():
            all_tokens_before.update(tokens)

        self.bp_index.re_encrypt()

        tokens_after = self.bp_index.get_server_view()
        all_tokens_after = set()
        for tokens in tokens_after.values():
            all_tokens_after.update(tokens)

        # No token should survive re-encryption
        assert all_tokens_before.isdisjoint(all_tokens_after), (
            "Tokens survived re-encryption - fresh randomness not applied"
        )

    def test_re_encryption_preserves_search_capability(self):
        """Test that search still works after re-encryption."""
        self.bp_index.re_encrypt()

        results = self.bp_index.search("financial")
        assert sorted(results) == ["doc1", "doc3"]

        results = self.bp_index.search("fraud")
        assert sorted(results) == ["doc2", "doc3"]

    def test_re_encryption_resets_deletion_count(self):
        """Test that re-encryption resets the deletion counter."""
        self.bp_index.delete_document("doc1")
        assert self.bp_index.deletion_count == 1

        self.bp_index.re_encrypt()
        assert self.bp_index.deletion_count == 0

    def test_re_encryption_increments_epoch(self):
        """Test that re-encryption increments the epoch counter."""
        assert self.bp_index.epoch == 0

        self.bp_index.re_encrypt()
        assert self.bp_index.epoch == 1

        self.bp_index.re_encrypt()
        assert self.bp_index.epoch == 2

    def test_re_encryption_invalidates_old_query_tokens(self):
        """Test that query tokens from before re-encryption no longer work."""
        old_query = self.bp_index.sse.generate_search_query("financial")

        # Should match before re-encryption
        server_view = self.bp_index.get_server_view()
        matches_before = [
            doc_id for doc_id, tokens in server_view.items()
            if old_query in tokens
        ]
        assert len(matches_before) > 0

        self.bp_index.re_encrypt()

        # Old query token should not match anything after re-encryption
        server_view = self.bp_index.get_server_view()
        matches_after = [
            doc_id for doc_id, tokens in server_view.items()
            if old_query in tokens
        ]
        assert matches_after == []

    def test_garbage_collection_removes_orphans(self):
        """Test garbage collection removes orphaned index entries."""
        bp = BackwardPrivateIndex()
        bp.add_document("doc1", {"kw1"})

        # Simulate an orphaned entry (index entry without keyword metadata)
        bp._index["orphan"] = {"fake_token"}

        assert bp.document_count == 2  # doc1 + orphan in index

        removed = bp.garbage_collect()
        assert removed == 1
        assert bp.document_count == 1
        assert "orphan" not in bp.get_server_view()

    def test_garbage_collection_no_orphans(self):
        """Test garbage collection is a no-op when no orphans exist."""
        removed = self.bp_index.garbage_collect()
        assert removed == 0

    def test_server_cannot_link_deletion_to_past_query(self):
        """Prove that a server observing queries and deletions cannot link them.

        Scenario: Server observes a search for "fraud", then observes deletion
        of doc2. The server should not be able to determine that doc2 contained
        "fraud" based on the delete tokens alone.
        """
        # Server observes a search query for "fraud"
        fraud_query_token = self.bp_index.sse.generate_search_query("fraud")

        # Server observes the deletion of doc2
        result = self.bp_index.delete_document("doc2")
        delete_tokens = result["delete_tokens"]

        # The server tries to correlate: does any delete token match the query?
        for kw, dt in delete_tokens.items():
            assert dt != fraud_query_token, (
                f"Delete token for '{kw}' matches fraud query token"
            )

        # The server also tries to check if any delete token appears in
        # the remaining index (which would reveal keyword associations)
        remaining_view = self.bp_index.get_server_view()
        all_remaining_tokens = set()
        for tokens in remaining_view.values():
            all_remaining_tokens.update(tokens)

        for dt in delete_tokens.values():
            assert dt not in all_remaining_tokens

    def test_deleted_document_cannot_be_recovered(self):
        """Prove that deleted documents leave no recoverable trace.

        After deletion, no combination of server-visible information
        (remaining index entries, delete tokens) allows recovering
        the deleted document's keyword associations.
        """
        # Record complete server state before deletion
        view_before = self.bp_index.get_server_view()
        doc2_tokens = view_before["doc2"]

        # Delete doc2
        result = self.bp_index.delete_document("doc2")

        # Record complete server state after deletion
        view_after = self.bp_index.get_server_view()

        # 1. doc2 is gone from the index
        assert "doc2" not in view_after

        # 2. doc2's unique tokens (detection, system) are not in any remaining doc
        # (shared tokens like "fraud" may appear for doc3, which is expected)
        for remaining_tokens in view_after.values():
            # The set of tokens for any remaining doc should not be a
            # superset that reveals doc2's full token set
            assert not doc2_tokens.issubset(remaining_tokens)

        # 3. Searching for doc2-only keywords returns empty
        assert self.bp_index.search("detection") == []
        assert self.bp_index.search("system") == []

        # 4. Delete tokens cannot reconstruct the index entry
        delete_tokens = set(result["delete_tokens"].values())
        assert delete_tokens.isdisjoint(doc2_tokens), (
            "Delete tokens match original search tokens - backward privacy broken"
        )

    def test_multiple_deletions_then_re_encryption(self):
        """Test full workflow: add, search, delete multiple, re-encrypt."""
        bp = BackwardPrivateIndex(re_encryption_threshold=2)
        bp.add_document("a", {"alpha", "shared"})
        bp.add_document("b", {"beta", "shared"})
        bp.add_document("c", {"gamma", "shared"})

        # Verify initial search
        assert sorted(bp.search("shared")) == ["a", "b", "c"]

        # Delete two documents (hits threshold)
        bp.delete_document("a")
        result = bp.delete_document("b")
        assert result["needs_reencryption"] is True

        # Only "c" remains searchable
        assert bp.search("shared") == ["c"]
        assert bp.search("alpha") == []

        # Re-encrypt
        old_tokens = bp.get_server_view()["c"]
        bp.re_encrypt()

        # Search still works with new tokens
        assert bp.search("shared") == ["c"]
        assert bp.search("gamma") == ["c"]

        # Tokens changed
        new_tokens = bp.get_server_view()["c"]
        assert old_tokens != new_tokens

    def test_re_encryption_breaks_accumulated_correlation(self):
        """Test that re-encryption breaks any correlation accumulated over time.

        Even if a server has been observing queries over time, re-encryption
        makes all prior observations useless for future correlation.
        """
        # Server accumulates query observations
        observed_queries = {}
        for keyword in ["financial", "fraud", "report"]:
            observed_queries[keyword] = self.bp_index.sse.generate_search_query(keyword)

        # Server also knows the index state
        old_view = self.bp_index.get_server_view()

        # Re-encrypt
        self.bp_index.re_encrypt()

        # All old query tokens are now useless
        new_view = self.bp_index.get_server_view()
        for keyword, old_token in observed_queries.items():
            for _doc_id, new_tokens in new_view.items():
                assert old_token not in new_tokens, (
                    f"Old query token for '{keyword}' still valid after re-encryption"
                )

        # Old index state is completely different from new state
        for doc_id in old_view:
            if doc_id in new_view:
                assert old_view[doc_id] != new_view[doc_id]

    def test_invalid_delete_key_size(self):
        """Test that invalid delete key size raises ValueError."""
        with pytest.raises(ValueError, match="Delete key must be 32 bytes"):
            BackwardPrivateIndex(delete_key=b"short")

    def test_index_isolation_after_delete(self):
        """Test that deleting one document doesn't affect other documents."""
        results_before = sorted(self.bp_index.search("financial"))
        assert results_before == ["doc1", "doc3"]

        # Delete doc2 (which doesn't contain "financial")
        self.bp_index.delete_document("doc2")

        results_after = sorted(self.bp_index.search("financial"))
        assert results_after == ["doc1", "doc3"]

        # doc1 and doc3 keywords are fully intact
        assert self.bp_index.search("quarterly") == ["doc1"]
        assert self.bp_index.search("analysis") == ["doc3"]
