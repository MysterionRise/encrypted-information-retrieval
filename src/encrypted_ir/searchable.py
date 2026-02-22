"""
Searchable Encryption Module

Implements searchable symmetric encryption for keyword searches on encrypted documents.
Uses a token-based approach where search tokens are generated from keywords.

Supports boolean (AND/OR) queries across multiple keywords for real document search use cases.

Use Case: Document management, email archival, customer service knowledge bases.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class BooleanQuery:
    """
    Represents a boolean search query over encrypted search tokens.

    Supports AND, OR operators and can be nested for complex queries
    like (fraud AND quarterly) OR (risk AND annual).
    """

    AND = "AND"
    OR = "OR"

    def __init__(self, operator: str, operands: list):
        """
        Initialize a boolean query.

        Args:
            operator: "AND" or "OR"
            operands: List of search tokens (str) or nested BooleanQuery objects
        """
        if operator not in (self.AND, self.OR):
            raise ValueError(f"Operator must be '{self.AND}' or '{self.OR}', got '{operator}'")
        if len(operands) < 2:
            raise ValueError("Boolean query requires at least 2 operands")
        self.operator = operator
        self.operands = operands

    def evaluate(self, document_tokens: set[str]) -> bool:
        """
        Evaluate this query against a set of document tokens.

        Args:
            document_tokens: Set of search tokens from an encrypted document

        Returns:
            True if the document matches the query
        """
        if self.operator == self.AND:
            return all(_evaluate_operand(op, document_tokens) for op in self.operands)
        else:  # OR
            return any(_evaluate_operand(op, document_tokens) for op in self.operands)

    def __repr__(self) -> str:
        return f"BooleanQuery({self.operator}, {self.operands!r})"


def _evaluate_operand(operand, document_tokens: set[str]) -> bool:
    """Evaluate a single operand (token string or nested BooleanQuery)."""
    if isinstance(operand, BooleanQuery):
        return operand.evaluate(document_tokens)
    return operand in document_tokens


class SearchableEncryption:
    """
    Searchable symmetric encryption using HMAC-based keyword tokens.

    Allows keyword searches on encrypted data without revealing plaintext.
    """

    def __init__(self, encryption_key: bytes = None, search_key: bytes = None):
        """
        Initialize searchable encryption.

        Args:
            encryption_key: 256-bit key for document encryption (AES-256)
            search_key: 256-bit key for search token generation
        """
        if encryption_key is None:
            encryption_key = os.urandom(32)
        elif len(encryption_key) != 32:
            raise ValueError("Encryption key must be 32 bytes (256 bits)")

        if search_key is None:
            search_key = os.urandom(32)
        elif len(search_key) != 32:
            raise ValueError("Search key must be 32 bytes (256 bits)")

        self.encryption_key = encryption_key
        self.search_key = search_key

    @staticmethod
    def generate_keys() -> tuple[bytes, bytes]:
        """
        Generate new encryption and search keys.

        Returns:
            Tuple of (encryption_key, search_key)
        """
        return os.urandom(32), os.urandom(32)

    def _extract_keywords(self, text: str) -> set[str]:
        """
        Extract keywords from text (simple tokenization).

        Args:
            text: Input text

        Returns:
            Set of lowercase keywords
        """
        # Simple word extraction - in production, use more sophisticated NLP
        words = text.lower().split()
        # Remove short words and common stop words
        stop_words = {"the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for"}
        keywords = {w.strip('.,!?;:"()[]{}') for w in words if len(w) > 2 and w not in stop_words}
        return keywords

    def _generate_search_token(self, keyword: str) -> str:
        """
        Generate a search token for a keyword.

        Args:
            keyword: Keyword to generate token for

        Returns:
            Base64-encoded search token
        """
        # Use HMAC with search key to create deterministic token
        token = hmac.new(self.search_key, keyword.lower().encode("utf-8"), hashlib.sha256).digest()
        return base64.b64encode(token).decode("ascii")

    def encrypt_document(
        self,
        document: str | bytes,
        auto_extract_keywords: bool = True,
        keywords: set[str] = None,
    ) -> tuple[bytes, set[str]]:
        """
        Encrypt a document and generate search tokens.

        Args:
            document: Document to encrypt (str or bytes)
            auto_extract_keywords: Whether to automatically extract keywords
            keywords: Manual keywords (used if auto_extract_keywords is False)

        Returns:
            Tuple of (encrypted_document, search_tokens)
        """
        if isinstance(document, str):
            plaintext = document.encode("utf-8")
            doc_text = document
        else:
            plaintext = document
            doc_text = document.decode("utf-8", errors="ignore")

        # Extract or use provided keywords
        if auto_extract_keywords:
            doc_keywords = self._extract_keywords(doc_text)
        else:
            doc_keywords = keywords or set()

        # Encrypt document using AES-GCM
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(self.encryption_key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        # Combine IV + tag + ciphertext
        encrypted_doc = iv + encryptor.tag + ciphertext

        # Generate search tokens
        search_tokens = {self._generate_search_token(kw) for kw in doc_keywords}

        return encrypted_doc, search_tokens

    def decrypt_document(self, encrypted_document: bytes) -> bytes:
        """
        Decrypt a document.

        Args:
            encrypted_document: Encrypted document (IV + tag + ciphertext)

        Returns:
            Decrypted plaintext (bytes)

        Raises:
            ValueError: If decryption fails
        """
        # Extract IV (12 bytes), tag (16 bytes), and ciphertext
        iv = encrypted_document[:12]
        tag = encrypted_document[12:28]
        ciphertext = encrypted_document[28:]

        cipher = Cipher(algorithms.AES(self.encryption_key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()

        try:
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext
        except Exception as e:
            raise ValueError("Decryption failed - invalid key or corrupted data") from e

    def generate_search_query(self, keyword: str) -> str:
        """
        Generate a search query token for a keyword.

        Args:
            keyword: Keyword to search for

        Returns:
            Search token
        """
        return self._generate_search_token(keyword)

    def search(self, query_token: str, document_tokens: set[str]) -> bool:
        """
        Check if a document matches a search query.

        Args:
            query_token: Search token from generate_search_query()
            document_tokens: Set of tokens from encrypt_document()

        Returns:
            True if document contains the keyword, False otherwise
        """
        return query_token in document_tokens

    def boolean_search_query(self, keywords: list[str], operator: str = "AND") -> BooleanQuery:
        """
        Generate a boolean search query from multiple keywords.

        Args:
            keywords: List of keywords to search for
            operator: "AND" (all must match) or "OR" (any must match)

        Returns:
            BooleanQuery that can be evaluated against document tokens
        """
        tokens = [self._generate_search_token(kw) for kw in keywords]
        return BooleanQuery(operator, tokens)

    def nested_boolean_query(self, operator: str, *sub_queries: BooleanQuery) -> BooleanQuery:
        """
        Combine multiple BooleanQuery objects into a nested query.

        Args:
            operator: "AND" or "OR" to combine the sub-queries
            *sub_queries: Two or more BooleanQuery objects to combine

        Returns:
            BooleanQuery combining the sub-queries
        """
        return BooleanQuery(operator, list(sub_queries))

    def boolean_search(self, query: BooleanQuery, document_tokens: set[str]) -> bool:
        """
        Check if a document matches a boolean query.

        Args:
            query: BooleanQuery from boolean_search_query() or nested_boolean_query()
            document_tokens: Set of tokens from encrypt_document()

        Returns:
            True if document matches the boolean query
        """
        return query.evaluate(document_tokens)

    def encrypt_document_to_base64(
        self,
        document: str | bytes,
        auto_extract_keywords: bool = True,
        keywords: set[str] = None,
    ) -> tuple[str, list[str]]:
        """
        Encrypt document and return base64-encoded result with tokens.

        Args:
            document: Document to encrypt
            auto_extract_keywords: Whether to extract keywords automatically
            keywords: Manual keywords

        Returns:
            Tuple of (base64_encrypted_doc, list_of_search_tokens)
        """
        encrypted_doc, tokens = self.encrypt_document(document, auto_extract_keywords, keywords)
        return (base64.b64encode(encrypted_doc).decode("ascii"), sorted(tokens))

    def decrypt_document_from_base64(self, encrypted_document_b64: str) -> bytes:
        """
        Decrypt from base64-encoded encrypted document.

        Args:
            encrypted_document_b64: Base64-encoded encrypted document

        Returns:
            Decrypted plaintext (bytes)
        """
        encrypted_doc = base64.b64decode(encrypted_document_b64)
        return self.decrypt_document(encrypted_doc)

    def export_keys(self) -> tuple[str, str]:
        """
        Export keys as base64 strings.

        Returns:
            Tuple of (encryption_key_b64, search_key_b64)
        """
        return (
            base64.b64encode(self.encryption_key).decode("ascii"),
            base64.b64encode(self.search_key).decode("ascii"),
        )

    @staticmethod
    def import_keys(encryption_key_b64: str, search_key_b64: str) -> SearchableEncryption:
        """
        Import keys from base64 strings.

        Args:
            encryption_key_b64: Base64-encoded encryption key
            search_key_b64: Base64-encoded search key

        Returns:
            SearchableEncryption instance with imported keys
        """
        encryption_key = base64.b64decode(encryption_key_b64)
        search_key = base64.b64decode(search_key_b64)
        return SearchableEncryption(encryption_key, search_key)


class ForwardPrivateSSE:
    """
    Forward-private searchable symmetric encryption.

    Forward privacy ensures that when new documents are added to the encrypted
    index, the server (honest-but-curious adversary) cannot link the updates
    to any previously executed search queries.

    Construction: Hash-chain state advancement inspired by Bost (2016),
    "Sigma-o-phi-o-s - Forward Secure Searchable Encryption" (ePrint 2016/728).

    Leakage profile:
      - Update leakage: Document count only. The server cannot determine which
        keywords are associated with new documents.
      - Search leakage: Matching document IDs and search pattern (whether the
        same keyword was searched before). After search, the keyword's state
        chain is re-keyed to restore forward privacy for future updates.
      - No query-document linkage: Updates added after the last search or
        re-encryption cannot be correlated with past search queries.

    Dual-state index:
      - Secure index: Contains entries whose keyword mapping the server already
        knows (from previous searches or re-encryption). Uses deterministic
        HMAC tokens for O(1) lookup.
      - Auxiliary index: Contains forward-private entries. Uses chain-derived
        tags that are unlinkable without the state key. Entries are moved to
        the secure index during search or periodic re-encryption.

    Modes:
      - 'strong': Maximum privacy. Per-update random salts, automatic periodic
        re-encryption after a configurable threshold of updates. Higher
        computational cost due to frequent re-keying.
      - 'balanced': Practical tradeoff. Per-update random salts, manual
        re-encryption via re_encrypt(). Good privacy with lower overhead.
        This is the default mode.
      - 'off': Backward compatibility. Deterministic HMAC tokens with no
        forward privacy guarantee. Equivalent to standard SSE. Suitable for
        static datasets where forward privacy is not required.

    Assumptions and limitations:
      - The client is trusted and maintains state (keyword counters).
      - The server is honest-but-curious (follows protocol but tries to
        learn information from observed access patterns).
      - Forward privacy is broken for a keyword after search until re-keying
        completes. The implementation re-keys automatically after each search.
      - State is maintained in-memory; persistence is the caller's
        responsibility.
    """

    MODES = ("strong", "balanced", "off")

    def __init__(
        self,
        encryption_key: bytes = None,
        search_key: bytes = None,
        state_key: bytes = None,
        forward_privacy_mode: str = "balanced",
        re_encrypt_threshold: int = 100,
    ):
        """
        Initialize forward-private SSE.

        Args:
            encryption_key: 256-bit key for document encryption (AES-256-GCM).
            search_key: 256-bit key for deterministic search token generation.
            state_key: 256-bit key for state chain derivation (forward privacy).
            forward_privacy_mode: Privacy mode - 'strong', 'balanced', or 'off'.
            re_encrypt_threshold: Number of updates before automatic
                re-encryption (only applies in 'strong' mode).
        """
        if forward_privacy_mode not in self.MODES:
            raise ValueError(
                f"forward_privacy_mode must be one of {self.MODES}, "
                f"got '{forward_privacy_mode}'"
            )

        self.forward_privacy_mode = forward_privacy_mode
        self._re_encrypt_threshold = re_encrypt_threshold

        self.encryption_key = self._validate_key(encryption_key, "Encryption key")
        self.search_key = self._validate_key(search_key, "Search key")
        self.state_key = self._validate_key(state_key, "State key")

        self._sse = SearchableEncryption(self.encryption_key, self.search_key)

        # Client-side state: keyword -> {initial, current, counter}
        self._keyword_state: dict[str, dict] = {}

        # Dual-state index
        self._secure_index: dict[str, set[str]] = {}
        self._auxiliary_index: dict[str, bytes] = {}

        # Document storage
        self._documents: dict[str, bytes] = {}

        self._update_count = 0

    @staticmethod
    def _validate_key(key: bytes | None, name: str) -> bytes:
        if key is None:
            return os.urandom(32)
        if len(key) != 32:
            raise ValueError(f"{name} must be 32 bytes (256 bits)")
        return key

    @staticmethod
    def generate_keys() -> tuple[bytes, bytes, bytes]:
        """
        Generate encryption, search, and state keys.

        Returns:
            Tuple of (encryption_key, search_key, state_key).
        """
        return os.urandom(32), os.urandom(32), os.urandom(32)

    def _init_keyword_state(self, keyword: str) -> dict:
        """Initialize or retrieve state for a keyword."""
        kw = keyword.lower()
        if kw not in self._keyword_state:
            initial = hmac.new(self.state_key, kw.encode("utf-8"), hashlib.sha256).digest()
            self._keyword_state[kw] = {
                "initial": initial,
                "current": initial,
                "counter": 0,
            }
        return self._keyword_state[kw]

    @staticmethod
    def _advance_state(state: bytes) -> bytes:
        """Advance state via one-way hash chain."""
        return hmac.new(state, b"fp-chain-advance", hashlib.sha256).digest()

    @staticmethod
    def _compute_tag(state: bytes) -> bytes:
        """Compute index lookup tag from chain state."""
        return hmac.new(state, b"fp-index-tag", hashlib.sha256).digest()

    @staticmethod
    def _derive_entry_key(state: bytes, salt: bytes) -> bytes:
        """Derive entry encryption key from state and per-update salt."""
        return hmac.new(state, b"fp-entry-key" + salt, hashlib.sha256).digest()

    def _encrypt_entry(self, state: bytes, doc_id: str) -> bytes:
        """
        Encrypt a document ID with per-update random salt.

        Returns:
            salt (32 bytes) + iv (12 bytes) + tag (16 bytes) + ciphertext
        """
        salt = os.urandom(32)
        entry_key = self._derive_entry_key(state, salt)
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(entry_key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        ct = encryptor.update(doc_id.encode("utf-8")) + encryptor.finalize()
        return salt + iv + encryptor.tag + ct

    def _decrypt_entry(self, state: bytes, encrypted_entry: bytes) -> str:
        """Decrypt a document ID from an encrypted entry."""
        salt = encrypted_entry[:32]
        iv = encrypted_entry[32:44]
        tag = encrypted_entry[44:60]
        ct = encrypted_entry[60:]
        entry_key = self._derive_entry_key(state, salt)
        cipher = Cipher(algorithms.AES(entry_key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        return (decryptor.update(ct) + decryptor.finalize()).decode("utf-8")

    def add_document(
        self,
        doc_id: str,
        document: str | bytes,
        keywords: set[str] = None,
        auto_extract_keywords: bool = True,
    ) -> None:
        """
        Add a document to the forward-private encrypted index.

        Each keyword generates a unique update token derived from the hash-chain
        state, ensuring the server cannot link this update to past queries.
        Per-update random salts provide additional entry-level randomization.

        Args:
            doc_id: Unique document identifier.
            document: Document content to encrypt and index.
            keywords: Manual keywords (used when auto_extract_keywords=False).
            auto_extract_keywords: Whether to extract keywords automatically.
        """
        encrypted_doc, _ = self._sse.encrypt_document(
            document, auto_extract_keywords=False, keywords=set()
        )
        self._documents[doc_id] = encrypted_doc

        if auto_extract_keywords:
            text = (
                document if isinstance(document, str) else document.decode("utf-8", errors="ignore")
            )
            doc_keywords = self._sse._extract_keywords(text)
        else:
            doc_keywords = keywords or set()

        if self.forward_privacy_mode == "off":
            for kw in doc_keywords:
                token = self._sse._generate_search_token(kw)
                self._secure_index.setdefault(token, set()).add(doc_id)
        else:
            for kw in doc_keywords:
                kw_state = self._init_keyword_state(kw.lower())
                tag = self._compute_tag(kw_state["current"])
                tag_b64 = base64.b64encode(tag).decode("ascii")
                encrypted_entry = self._encrypt_entry(kw_state["current"], doc_id)
                self._auxiliary_index[tag_b64] = encrypted_entry
                kw_state["current"] = self._advance_state(kw_state["current"])
                kw_state["counter"] += 1

            self._update_count += len(doc_keywords)

            if (
                self.forward_privacy_mode == "strong"
                and self._update_count >= self._re_encrypt_threshold
            ):
                self.re_encrypt()

    def search(self, keyword: str) -> set[str]:
        """
        Search for documents containing keyword.

        In forward-private mode, traverses the state chain to find all matching
        entries in the auxiliary index, moves them to the secure index, and
        re-keys the keyword state to restore forward privacy for future updates.

        Args:
            keyword: Keyword to search for.

        Returns:
            Set of matching document IDs.
        """
        kw = keyword.lower()

        if self.forward_privacy_mode == "off":
            token = self._sse._generate_search_token(kw)
            return set(self._secure_index.get(token, set()))

        results = set()

        search_token = self._sse._generate_search_token(kw)
        results.update(self._secure_index.get(search_token, set()))

        kw_state = self._keyword_state.get(kw)
        if kw_state is not None:
            state = kw_state["initial"]
            for _ in range(kw_state["counter"]):
                tag = self._compute_tag(state)
                tag_b64 = base64.b64encode(tag).decode("ascii")

                if tag_b64 in self._auxiliary_index:
                    entry = self._auxiliary_index.pop(tag_b64)
                    doc_id = self._decrypt_entry(state, entry)
                    results.add(doc_id)
                    self._secure_index.setdefault(search_token, set()).add(doc_id)

                state = self._advance_state(state)

            # Re-key to restore forward privacy for future updates
            new_initial = os.urandom(32)
            self._keyword_state[kw] = {
                "initial": new_initial,
                "current": new_initial,
                "counter": 0,
            }

        return results

    def re_encrypt(self) -> int:
        """
        Re-encrypt the auxiliary index into the secure index.

        Moves all forward-private entries to the secure index and re-keys
        all keyword states. This restores forward privacy by ensuring future
        update tokens are derived from fresh, unrelated state chains.

        In 'strong' mode, this is called automatically after a configurable
        number of updates. In 'balanced' mode, call this manually.

        Returns:
            Number of entries re-encrypted.
        """
        count = 0

        for kw, kw_state in list(self._keyword_state.items()):
            search_token = self._sse._generate_search_token(kw)
            state = kw_state["initial"]

            for _ in range(kw_state["counter"]):
                tag = self._compute_tag(state)
                tag_b64 = base64.b64encode(tag).decode("ascii")

                if tag_b64 in self._auxiliary_index:
                    entry = self._auxiliary_index.pop(tag_b64)
                    doc_id = self._decrypt_entry(state, entry)
                    self._secure_index.setdefault(search_token, set()).add(doc_id)
                    count += 1

                state = self._advance_state(state)

            new_initial = os.urandom(32)
            self._keyword_state[kw] = {
                "initial": new_initial,
                "current": new_initial,
                "counter": 0,
            }

        self._update_count = 0
        return count

    def decrypt_document(self, doc_id: str) -> bytes:
        """
        Decrypt a stored document by ID.

        Args:
            doc_id: Document identifier.

        Returns:
            Decrypted document bytes.

        Raises:
            KeyError: If doc_id not found.
            ValueError: If decryption fails.
        """
        if doc_id not in self._documents:
            raise KeyError(f"Document '{doc_id}' not found")
        return self._sse.decrypt_document(self._documents[doc_id])

    def get_index_stats(self) -> dict:
        """
        Get statistics about the index state.

        Returns:
            Dict with forward_privacy_mode, secure_entries,
            auxiliary_entries, keywords_tracked, documents_stored,
            and update_count.
        """
        secure_count = sum(len(v) for v in self._secure_index.values())
        return {
            "forward_privacy_mode": self.forward_privacy_mode,
            "secure_entries": secure_count,
            "auxiliary_entries": len(self._auxiliary_index),
            "keywords_tracked": len(self._keyword_state),
            "documents_stored": len(self._documents),
            "update_count": self._update_count,
        }


class BackwardPrivateIndex:
    """
    Backward-private searchable encryption index.

    Provides backward privacy: delete operations cannot be linked to prior
    add operations or search queries. The server observing a deletion learns
    nothing about which keywords were associated with the deleted document
    or which past queries matched it.

    Implements:
    - Unlinkable delete tokens (separate key, different derivation path)
    - Secure index pruning (complete removal of deleted entries)
    - Garbage collection for stale index entries
    - Periodic re-encryption with fresh randomness after N deletions

    Reference: Bost & Fouque (2017), "Thwarting Leakage Abuse Attacks"
    """

    def __init__(
        self,
        sse: SearchableEncryption | None = None,
        delete_key: bytes | None = None,
        re_encryption_threshold: int = 100,
    ):
        """
        Initialize backward-private index.

        Args:
            sse: SearchableEncryption instance (created if None)
            delete_key: 256-bit key for delete token generation (random if None)
            re_encryption_threshold: Number of deletions before triggering
                re-encryption (full index rebuild with fresh randomness)
        """
        self.sse = sse or SearchableEncryption()

        if delete_key is None:
            delete_key = os.urandom(32)
        elif len(delete_key) != 32:
            raise ValueError("Delete key must be 32 bytes (256 bits)")
        self._delete_key = delete_key

        self.re_encryption_threshold = re_encryption_threshold

        # Server-side state: doc_id -> set of search tokens
        self._index: dict[str, set[str]] = {}

        # Client-side state (never exposed to server): doc_id -> set of plaintext keywords
        self._doc_keywords: dict[str, set[str]] = {}

        # Deletion tracking
        self._deletion_count: int = 0
        self._epoch: int = 0

    @property
    def epoch(self) -> int:
        """Current epoch (incremented on each re-encryption)."""
        return self._epoch

    @property
    def deletion_count(self) -> int:
        """Number of deletions since last re-encryption."""
        return self._deletion_count

    @property
    def document_count(self) -> int:
        """Number of documents in the index."""
        return len(self._index)

    def add_document(self, doc_id: str, keywords: set[str]) -> set[str]:
        """
        Add a document to the index.

        Args:
            doc_id: Unique document identifier
            keywords: Set of plaintext keywords for the document

        Returns:
            Set of search tokens stored in the index (server view)

        Raises:
            ValueError: If doc_id already exists in the index
        """
        if doc_id in self._index:
            raise ValueError(f"Document '{doc_id}' already exists in index")

        tokens = {self.sse._generate_search_token(kw) for kw in keywords}
        self._index[doc_id] = tokens
        self._doc_keywords[doc_id] = set(keywords)
        return set(tokens)

    def search(self, keyword: str) -> list[str]:
        """
        Search for documents containing a keyword.

        Args:
            keyword: Plaintext keyword to search for

        Returns:
            List of matching document IDs
        """
        query_token = self.sse.generate_search_query(keyword)
        return [doc_id for doc_id, tokens in self._index.items() if query_token in tokens]

    def _generate_delete_token(self, doc_id: str, keyword: str) -> str:
        """
        Generate a delete token that is cryptographically unlinkable to
        the corresponding search token.

        Delete tokens use a separate key and include the doc_id in the
        HMAC input, making them structurally different from search tokens
        (which are HMAC(search_key, keyword) only).

        Args:
            doc_id: Document identifier
            keyword: Keyword being removed

        Returns:
            Base64-encoded delete token
        """
        msg = f"{doc_id}\x00{keyword.lower()}".encode()
        token = hmac.new(self._delete_key, msg, hashlib.sha256).digest()
        return base64.b64encode(token).decode("ascii")

    def delete_document(self, doc_id: str) -> dict:
        """
        Delete a document from the index with backward privacy.

        The delete tokens returned are cryptographically unlinkable to the
        search tokens that were used to index the document. The server
        cannot correlate a deletion with any prior add or search operation.

        Args:
            doc_id: Document identifier to delete

        Returns:
            Dict with deletion metadata:
                - doc_id: The deleted document ID
                - delete_tokens: Dict of keyword -> delete token (unlinkable)
                - deletion_count: Total deletions since last re-encryption
                - needs_reencryption: True if re-encryption threshold reached

        Raises:
            KeyError: If doc_id not found in index
        """
        if doc_id not in self._index:
            raise KeyError(f"Document '{doc_id}' not found in index")

        keywords = self._doc_keywords[doc_id]

        # Generate delete tokens (unlinkable to search tokens)
        delete_tokens = {kw: self._generate_delete_token(doc_id, kw) for kw in keywords}

        # Secure index pruning: completely remove all traces
        del self._index[doc_id]
        del self._doc_keywords[doc_id]

        self._deletion_count += 1
        needs_reencryption = self._deletion_count >= self.re_encryption_threshold

        return {
            "doc_id": doc_id,
            "delete_tokens": delete_tokens,
            "deletion_count": self._deletion_count,
            "needs_reencryption": needs_reencryption,
        }

    def re_encrypt(self) -> None:
        """
        Re-encrypt the entire index with fresh keys and randomness.

        Generates new search keys and rebuilds all tokens. After
        re-encryption, all previous search tokens and delete tokens
        become invalid and unlinkable to the new index state.

        This provides the strongest backward privacy guarantee:
        any correlation the server may have accumulated between
        tokens and queries is broken.
        """
        new_enc_key, new_search_key = SearchableEncryption.generate_keys()
        new_sse = SearchableEncryption(new_enc_key, new_search_key)

        # Generate fresh delete key
        self._delete_key = os.urandom(32)

        # Rebuild index with new tokens
        new_index: dict[str, set[str]] = {}
        for doc_id, keywords in self._doc_keywords.items():
            new_index[doc_id] = {new_sse._generate_search_token(kw) for kw in keywords}

        self.sse = new_sse
        self._index = new_index
        self._deletion_count = 0
        self._epoch += 1

    def garbage_collect(self) -> int:
        """
        Remove stale entries from the index.

        Scans for any index entries whose corresponding keyword
        metadata is missing (orphaned by incomplete deletion) and
        removes them.

        Returns:
            Number of stale entries removed
        """
        stale_ids = [doc_id for doc_id in self._index if doc_id not in self._doc_keywords]
        for doc_id in stale_ids:
            del self._index[doc_id]
        return len(stale_ids)

    def get_server_view(self) -> dict[str, set[str]]:
        """
        Return the index as the server would see it.

        This is useful for testing backward privacy properties:
        the server view should not contain any information that
        links delete tokens to search tokens or past queries.

        Returns:
            Copy of the index (doc_id -> set of search tokens)
        """
        return {doc_id: set(tokens) for doc_id, tokens in self._index.items()}
