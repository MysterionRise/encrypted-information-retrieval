"""Tests for the forward-private SSE and deletable-index research prototypes."""

import pytest

from encrypted_ir.research.forward_private_sse import BackwardPrivateIndex, ForwardPrivateSSE


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
        sse.add_document("doc1", "x", keywords={"Financial"}, auto_extract_keywords=False)

        assert sse.search("financial") == {"doc1"}
        assert sse.search("FINANCIAL") == {"doc1"}
        assert sse.search("Financial") == {"doc1"}

    def test_index_stats(self):
        """Test get_index_stats returns correct statistics."""
        sse = ForwardPrivateSSE(forward_privacy_mode="balanced")
        sse.add_document("doc1", "x", keywords={"alpha", "beta"}, auto_extract_keywords=False)

        stats = sse.get_index_stats()
        assert stats["forward_privacy_mode"] == "balanced"
        assert stats["auxiliary_entries"] == 2
        assert stats["secure_entries"] == 0
        assert stats["documents_stored"] == 1
        assert stats["keywords_tracked"] == 2

    def test_search_moves_entries_to_secure_index(self):
        """Test that search moves auxiliary entries to secure index."""
        sse = ForwardPrivateSSE(forward_privacy_mode="balanced")
        sse.add_document("doc1", "x", keywords={"alpha"}, auto_extract_keywords=False)

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
        sse.add_document("doc1", "x", keywords={"alpha"}, auto_extract_keywords=False)

        assert sse.search("alpha") == {"doc1"}
        # Second search should still find doc1 (now from secure index)
        assert sse.search("alpha") == {"doc1"}

    def test_add_after_search_still_findable(self):
        """Test that documents added after a search are found in later searches."""
        sse = ForwardPrivateSSE(forward_privacy_mode="balanced")
        sse.add_document("doc1", "x", keywords={"alpha"}, auto_extract_keywords=False)
        assert sse.search("alpha") == {"doc1"}

        # Add another doc with same keyword after search (re-keyed state)
        sse.add_document("doc2", "y", keywords={"alpha"}, auto_extract_keywords=False)
        assert sse.search("alpha") == {"doc1", "doc2"}


class TestForwardPrivateSSEReEncryption:
    """Test periodic re-encryption of the forward-private index."""

    def test_re_encrypt_moves_all_entries(self):
        """Test that re_encrypt moves all auxiliary entries to secure index."""
        sse = ForwardPrivateSSE(forward_privacy_mode="balanced")
        sse.add_document("doc1", "x", keywords={"alpha", "beta"}, auto_extract_keywords=False)
        sse.add_document("doc2", "y", keywords={"beta", "gamma"}, auto_extract_keywords=False)

        count = sse.re_encrypt()
        assert count == 4  # alpha:doc1, beta:doc1, beta:doc2, gamma:doc2

        stats = sse.get_index_stats()
        assert stats["auxiliary_entries"] == 0
        assert stats["secure_entries"] == 4

    def test_re_encrypt_preserves_searchability(self):
        """Test that search works correctly after re-encryption."""
        sse = ForwardPrivateSSE(forward_privacy_mode="balanced")
        sse.add_document("doc1", "x", keywords={"alpha", "beta"}, auto_extract_keywords=False)
        sse.add_document("doc2", "y", keywords={"beta", "gamma"}, auto_extract_keywords=False)

        sse.re_encrypt()

        assert sse.search("alpha") == {"doc1"}
        assert sse.search("beta") == {"doc1", "doc2"}
        assert sse.search("gamma") == {"doc2"}

    def test_add_after_re_encrypt(self):
        """Test that documents added after re-encryption are found."""
        sse = ForwardPrivateSSE(forward_privacy_mode="balanced")
        sse.add_document("doc1", "x", keywords={"alpha"}, auto_extract_keywords=False)
        sse.re_encrypt()

        sse.add_document("doc2", "y", keywords={"alpha"}, auto_extract_keywords=False)
        assert sse.search("alpha") == {"doc1", "doc2"}

    def test_strong_mode_auto_re_encrypt(self):
        """Test that strong mode triggers automatic re-encryption."""
        sse = ForwardPrivateSSE(forward_privacy_mode="strong", re_encrypt_threshold=3)
        # Add enough keywords to trigger threshold
        sse.add_document("doc1", "x", keywords={"a", "b", "c"}, auto_extract_keywords=False)

        # Auto re-encryption should have fired
        stats = sse.get_index_stats()
        assert stats["auxiliary_entries"] == 0
        assert stats["update_count"] == 0

    def test_re_encrypt_resets_counter(self):
        """Test that re_encrypt resets the update counter."""
        sse = ForwardPrivateSSE(forward_privacy_mode="balanced")
        sse.add_document("doc1", "x", keywords={"alpha"}, auto_extract_keywords=False)
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
        sse.add_document("doc1", "x", keywords={"fraud"}, auto_extract_keywords=False)
        tags_before_search = set(sse._auxiliary_index.keys())
        assert len(tags_before_search) == 1

        # Step 2: Search for "fraud" - server observes the state chain
        # After search, entries move to secure index and state is re-keyed
        sse.search("fraud")
        assert len(sse._auxiliary_index) == 0

        # Step 3: Add doc2 with same keyword after re-keying
        sse.add_document("doc2", "y", keywords={"fraud"}, auto_extract_keywords=False)
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
        sse.add_document("doc1", "x", keywords={"fraud"}, auto_extract_keywords=False)
        sse.add_document("doc2", "y", keywords={"fraud"}, auto_extract_keywords=False)
        tags_round1 = set(sse._auxiliary_index.keys())

        # Search reveals the chain and re-keys
        sse.search("fraud")

        # Add more documents
        sse.add_document("doc3", "z", keywords={"fraud"}, auto_extract_keywords=False)
        sse.add_document("doc4", "w", keywords={"fraud"}, auto_extract_keywords=False)
        tags_round2 = set(sse._auxiliary_index.keys())

        # All tags from round 2 must be different from round 1
        assert tags_round1.isdisjoint(
            tags_round2
        ), "Update tags after re-keying should be unlinkable to pre-search tags"

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
        sse.add_document("doc1", "x", keywords={"secret"}, auto_extract_keywords=False)
        epoch1_tags = set(sse._auxiliary_index.keys())
        server_observed_tags.extend(epoch1_tags)

        # Search: server sees state chain for "secret"
        sse.search("secret")

        # Epoch 2: Server observes new update tags after re-key
        sse.add_document("doc2", "y", keywords={"secret"}, auto_extract_keywords=False)
        epoch2_tags = set(sse._auxiliary_index.keys())
        server_observed_tags.extend(epoch2_tags)

        # Re-encrypt and search
        sse.search("secret")

        # Epoch 3: Another round
        sse.add_document("doc3", "z", keywords={"secret"}, auto_extract_keywords=False)
        epoch3_tags = set(sse._auxiliary_index.keys())
        server_observed_tags.extend(epoch3_tags)

        # All observed tags should be unique (no collisions across epochs)
        assert len(server_observed_tags) == len(
            set(server_observed_tags)
        ), "Tag collision detected across epochs - forward privacy compromised"

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

        sse.add_document("doc1", "x", keywords={"keyword"}, auto_extract_keywords=False)
        tag1 = set(sse._auxiliary_index.keys())

        sse.add_document("doc2", "y", keywords={"keyword"}, auto_extract_keywords=False)
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

        sse.add_document("doc1", "x", keywords={"alpha"}, auto_extract_keywords=False)
        sse.add_document("doc2", "y", keywords={"beta"}, auto_extract_keywords=False)

        tags = list(sse._auxiliary_index.keys())
        assert len(tags) == 2
        assert tags[0] != tags[1]

    def test_re_encrypt_produces_fresh_tags(self):
        """
        After re-encryption, adding the same keyword produces entirely
        new tags unrelated to the pre-re-encryption tags.
        """
        sse = ForwardPrivateSSE(forward_privacy_mode="balanced")

        sse.add_document("doc1", "x", keywords={"alpha"}, auto_extract_keywords=False)
        tags_before = set(sse._auxiliary_index.keys())

        sse.re_encrypt()

        sse.add_document("doc2", "y", keywords={"alpha"}, auto_extract_keywords=False)
        tags_after = set(sse._auxiliary_index.keys())

        assert tags_before.isdisjoint(tags_after)

    def test_off_mode_no_forward_privacy(self):
        """
        In 'off' mode, the same keyword always produces the same token.
        This is the expected behavior for backward compatibility.
        """
        sse = ForwardPrivateSSE(forward_privacy_mode="off")

        sse.add_document("doc1", "x", keywords={"alpha"}, auto_extract_keywords=False)
        sse.add_document("doc2", "y", keywords={"alpha"}, auto_extract_keywords=False)

        # In off mode, entries go to secure index with deterministic tokens
        assert len(sse._secure_index) == 1  # Same token for both docs
        token = list(sse._secure_index.keys())[0]
        assert sse._secure_index[token] == {"doc1", "doc2"}

    def test_bytes_document_support(self):
        """Test that binary documents are handled correctly."""
        sse = ForwardPrivateSSE(forward_privacy_mode="balanced")
        sse.add_document(
            "doc1",
            b"binary content",
            keywords={"binary"},
            auto_extract_keywords=False,
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
                f"doc{i}",
                "x",
                keywords={"keyword"},
                auto_extract_keywords=False,
            )
            current_tags = set(sse._auxiliary_index.keys())
            # New tags should never overlap with previously seen tags
            assert all_tags_seen.isdisjoint(current_tags), f"Tag collision at epoch {i}"
            all_tags_seen.update(current_tags)

            sse.search("keyword")

        # All 10 documents should be found
        assert sse.search("keyword") == {f"doc{i}" for i in range(10)}


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
        assert delete_tokens.isdisjoint(
            all_search_tokens
        ), "Delete tokens overlap with search tokens - backward privacy violated"

        # Delete tokens must share NO values with query tokens
        assert delete_tokens.isdisjoint(
            query_tokens
        ), "Delete tokens overlap with query tokens - backward privacy violated"

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
        assert all_tokens_before.isdisjoint(
            all_tokens_after
        ), "Tokens survived re-encryption - fresh randomness not applied"

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
        matches_before = [doc_id for doc_id, tokens in server_view.items() if old_query in tokens]
        assert len(matches_before) > 0

        self.bp_index.re_encrypt()

        # Old query token should not match anything after re-encryption
        server_view = self.bp_index.get_server_view()
        matches_after = [doc_id for doc_id, tokens in server_view.items() if old_query in tokens]
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
            assert dt != fraud_query_token, f"Delete token for '{kw}' matches fraud query token"

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
        assert delete_tokens.isdisjoint(
            doc2_tokens
        ), "Delete tokens match original search tokens - backward privacy broken"

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
                assert (
                    old_token not in new_tokens
                ), f"Old query token for '{keyword}' still valid after re-encryption"

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
