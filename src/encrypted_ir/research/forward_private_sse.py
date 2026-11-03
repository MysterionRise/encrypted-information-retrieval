"""Dynamic searchable-encryption prototypes: forward-private SSE and a deletable index.

Research prototypes moved out of ``encrypted_ir.searchable``. They are not used by the
durable document path and are not audited. See docs/THREAT_MODEL.md for the leakage of each
construction.

Known limitations:

- ``ForwardPrivateSSE`` keeps the client state and the "server" index in one Python object,
  so no token ever crosses a trust boundary. The leakage statements describe what a server
  holding the index would observe.
- Client state (the hash-chain positions) lives in memory. Persist it with
  ``ForwardPrivateSSE.export_state()`` and restore it with ``import_state()``. A fresh
  instance with the same keys restarts every chain at its first position; ``add_document``
  then refuses to overwrite an existing index tag (``RuntimeError``) instead of silently
  replacing an entry.
- ``ForwardPrivateSSE`` has no deletion.
- ``BackwardPrivateIndex`` provides no backward privacy (see its docstring).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
from collections.abc import Mapping
from typing import Any, cast

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from ..searchable import SearchableEncryption

__all__ = ["ForwardPrivateSSE", "BackwardPrivateIndex"]

_CHAIN_STATE_SIZE = 32


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode(value: str, expected_length: int | None = None) -> bytes:
    if not isinstance(value, str):
        raise TypeError("expected a base64 string")
    data = base64.b64decode(value.encode("ascii"), validate=True)
    if expected_length is not None and len(data) != expected_length:
        raise ValueError(f"expected {expected_length} bytes, got {len(data)}")
    return data


class ForwardPrivateSSE:
    """
    Hash-chain searchable encryption with a forward-privacy goal.

    Research prototype, not audited. The goal is that when new documents are
    added, an honest-but-curious server cannot link the updates to searches
    it has already seen.

    Construction: a custom per-keyword hash chain, loosely inspired by Bost
    (2016), "Sophos: Forward Secure Searchable Encryption" (ePrint 2016/728).
    It is not Sophos:
    - there is no trapdoor permutation,
    - the client walks the chain itself,
    - client state and the "server" index live in the same Python object, so
      no search token ever crosses a trust boundary.
    The forward-privacy argument rests on re-keying each keyword's chain to a
    fresh random state after every search.

    Leakage profile (forward-private modes):
      - Update leakage: the number of keywords per added document. Update tags
        come from per-keyword chains, so the server cannot tell which keyword a
        new entry belongs to, or link it to earlier searches.
      - Search leakage: matching document IDs, result size and the search
        pattern (whether the same keyword was searched before).

    Index structures:
      - Auxiliary index: forward-private entries under chain-derived tags that
        are unlinkable without the client's chain state.
      - Secure index: entries under deterministic HMAC(search_key, keyword)
        tokens. Only 'balanced' and 'off' modes write to it.

    Modes:
      - 'strong': entries never leave the auxiliary index. A search drains the
        keyword's chain and re-inserts the matches under a fresh random chain.
        re_encrypt() re-randomises every chain in place, and runs automatically
        after ``re_encrypt_threshold`` updates. Nothing is ever written to the
        deterministic secure index, so strong mode leaks no keyword
        co-occurrence for keywords that were never searched.
      - 'balanced' (default): a search moves the keyword's matches into the
        secure index under the deterministic token. re_encrypt() runs only when
        called and moves every auxiliary entry into the secure index; after it,
        the server can see which documents share each keyword, including
        keywords that were never searched.
      - 'off': deterministic HMAC tokens with no forward privacy. Equivalent to
        standard SSE; suitable for static datasets.

    Assumptions and limitations:
      - The client is trusted and maintains state (keyword chain positions).
      - The server is honest-but-curious.
      - State is in memory. Use export_state() and import_state() to persist
        it; the exported state contains chain secrets and must be protected
        like the keys.
      - Documents cannot be deleted.
    """

    MODES = ("strong", "balanced", "off")
    STATE_VERSION = 1

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
            re_encrypt_threshold: Number of keyword updates after which strong
                mode re-randomises its chains (ignored in the other modes).
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

    def _initial_state(self, kw: str) -> bytes:
        """First chain state of a keyword that has never been searched."""
        return hmac.new(self.state_key, kw.encode("utf-8"), hashlib.sha256).digest()

    def _init_keyword_state(self, keyword: str) -> dict:
        """Initialize or retrieve state for a keyword."""
        kw = keyword.lower()
        if kw not in self._keyword_state:
            initial = self._initial_state(kw)
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

    @classmethod
    def _tag_b64(cls, state: bytes) -> str:
        return _b64encode(cls._compute_tag(state))

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
        return cast(bytes, salt + iv + encryptor.tag + ct)

    def _decrypt_entry(self, state: bytes, encrypted_entry: bytes) -> str:
        """Decrypt a document ID from an encrypted entry."""
        salt = encrypted_entry[:32]
        iv = encrypted_entry[32:44]
        tag = encrypted_entry[44:60]
        ct = encrypted_entry[60:]
        entry_key = self._derive_entry_key(state, salt)
        cipher = Cipher(algorithms.AES(entry_key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        return cast(str, (decryptor.update(ct) + decryptor.finalize()).decode("utf-8"))

    def _drain_chain(self, kw_state: dict) -> list[str]:
        """Walk a keyword's chain, removing and decrypting every entry it reaches."""
        found = []
        state = kw_state["initial"]
        for _ in range(kw_state["counter"]):
            entry = self._auxiliary_index.pop(self._tag_b64(state), None)
            if entry is not None:
                found.append(self._decrypt_entry(state, entry))
            state = self._advance_state(state)
        return found

    def _start_fresh_chain(self, kw: str, doc_ids: list[str]) -> None:
        """Re-key ``kw`` to a random chain and insert ``doc_ids`` at its first positions."""
        initial = os.urandom(_CHAIN_STATE_SIZE)
        state = initial
        for doc_id in doc_ids:
            self._auxiliary_index[self._tag_b64(state)] = self._encrypt_entry(state, doc_id)
            state = self._advance_state(state)
        self._keyword_state[kw] = {"initial": initial, "current": state, "counter": len(doc_ids)}

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

        Raises:
            ValueError: If ``doc_id`` is already stored.
            RuntimeError: If a chain position is already occupied in the index, which
                means the client state is out of sync with the index (for example, a
                restarted instance whose state was not restored with import_state()).
                Nothing is changed.
        """
        if doc_id in self._documents:
            raise ValueError(f"Document '{doc_id}' already exists")

        if auto_extract_keywords:
            text = (
                document if isinstance(document, str) else document.decode("utf-8", errors="ignore")
            )
            doc_keywords = self._sse._extract_keywords(text)
        else:
            doc_keywords = keywords or set()
        normalized = sorted({kw.lower() for kw in doc_keywords})

        # Plan every chain update before changing anything, so a collision leaves no trace.
        planned: list[tuple[str, bytes, str]] = []
        if self.forward_privacy_mode != "off":
            for kw in normalized:
                kw_state = self._keyword_state.get(kw)
                current = kw_state["current"] if kw_state else self._initial_state(kw)
                tag_b64 = self._tag_b64(current)
                if tag_b64 in self._auxiliary_index:
                    raise RuntimeError(
                        "Index tag already in use: the client chain state is out of sync with "
                        "the index. Restore the saved state with import_state() before adding."
                    )
                planned.append((kw, current, tag_b64))

        encrypted_doc, _ = self._sse.encrypt_document(
            document, auto_extract_keywords=False, keywords=set()
        )
        self._documents[doc_id] = encrypted_doc

        if self.forward_privacy_mode == "off":
            for kw in normalized:
                token = self._sse._generate_search_token(kw)
                self._secure_index.setdefault(token, set()).add(doc_id)
            return

        for kw, current, tag_b64 in planned:
            kw_state = self._init_keyword_state(kw)
            self._auxiliary_index[tag_b64] = self._encrypt_entry(current, doc_id)
            kw_state["current"] = self._advance_state(current)
            kw_state["counter"] += 1

        self._update_count += len(planned)

        if (
            self.forward_privacy_mode == "strong"
            and self._update_count >= self._re_encrypt_threshold
        ):
            self.re_encrypt()

    def search(self, keyword: str) -> set[str]:
        """
        Search for documents containing keyword.

        In the forward-private modes, walks the keyword's state chain to find
        all its entries in the auxiliary index, then re-keys the keyword to a
        fresh random chain so that later updates cannot be linked to this
        search. Balanced mode moves the matches into the secure index; strong
        mode re-inserts them under the fresh chain.

        Args:
            keyword: Keyword to search for.

        Returns:
            Set of matching document IDs.
        """
        kw = keyword.lower()

        if self.forward_privacy_mode == "off":
            token = self._sse._generate_search_token(kw)
            return set(self._secure_index.get(token, set()))

        results: set[str] = set()
        search_token = None
        if self.forward_privacy_mode == "balanced":
            search_token = self._sse._generate_search_token(kw)
            results.update(self._secure_index.get(search_token, set()))

        kw_state = self._keyword_state.get(kw)
        if kw_state is not None:
            found = self._drain_chain(kw_state)
            results.update(found)
            if self.forward_privacy_mode == "strong":
                self._start_fresh_chain(kw, found)
            else:
                if found:
                    self._secure_index.setdefault(cast(str, search_token), set()).update(found)
                self._start_fresh_chain(kw, [])

        return results

    def re_encrypt(self) -> int:
        """
        Re-key every keyword chain.

        Strong mode: every auxiliary entry is decrypted and re-inserted under a
        fresh random chain, so the auxiliary index is re-randomised in place and
        nothing moves to the deterministic secure index. Called automatically
        after ``re_encrypt_threshold`` updates.

        Balanced mode: every auxiliary entry moves to the secure index, under
        the deterministic HMAC(search_key, keyword) token. After this call the
        server can see which documents share each keyword, including keywords
        that were never searched. Never called automatically.

        Returns:
            Number of entries re-encrypted.
        """
        count = 0

        for kw, kw_state in list(self._keyword_state.items()):
            found = self._drain_chain(kw_state)
            count += len(found)
            if self.forward_privacy_mode == "strong":
                self._start_fresh_chain(kw, found)
            else:
                if found:
                    search_token = self._sse._generate_search_token(kw)
                    self._secure_index.setdefault(search_token, set()).update(found)
                self._start_fresh_chain(kw, [])

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

    def _key_check(self) -> str:
        """Short PRF value of the three keys, so state is not imported under other keys."""
        digest = hmac.new(
            self.state_key,
            b"fp-export-key-check" + self.encryption_key + self.search_key,
            hashlib.sha256,
        ).digest()
        return _b64encode(digest[:16])

    def export_state(self) -> dict[str, Any]:
        """
        Export the client state and the index as a JSON-serialisable dict.

        The result holds the keyword chain positions, both index structures and
        the encrypted documents; bytes are base64 strings. It does not hold the
        keys, but it is client state: the keywords themselves appear in plaintext
        (as the keys of ``keyword_state``), and the chain states derive index tags
        and decrypt entries. Protect the export like key material.

        Returns:
            State dict for :meth:`import_state`.
        """
        return {
            "version": self.STATE_VERSION,
            "forward_privacy_mode": self.forward_privacy_mode,
            "key_check": self._key_check(),
            "update_count": self._update_count,
            "keyword_state": {
                kw: {
                    "initial": _b64encode(st["initial"]),
                    "current": _b64encode(st["current"]),
                    "counter": st["counter"],
                }
                for kw, st in self._keyword_state.items()
            },
            "secure_index": {token: sorted(ids) for token, ids in self._secure_index.items()},
            "auxiliary_index": {tag: _b64encode(e) for tag, e in self._auxiliary_index.items()},
            "documents": {doc_id: _b64encode(doc) for doc_id, doc in self._documents.items()},
        }

    def import_state(self, state: Mapping[str, Any]) -> None:
        """
        Restore state produced by :meth:`export_state` into this empty instance.

        The instance must have been created with the same three keys and the
        same mode. After the import, new updates continue each keyword's chain
        where the exporting instance stopped, so tags never collide.

        Args:
            state: Dict returned by export_state(), for example after a JSON round trip.

        Raises:
            ValueError: If the state is malformed, has another version or mode, was
                exported under different keys, or this instance already holds data.
        """
        if self._documents or self._keyword_state or self._secure_index or self._auxiliary_index:
            raise ValueError("import_state() needs an empty instance")
        try:
            if state["version"] != self.STATE_VERSION:
                raise ValueError(f"Unsupported state version: {state['version']!r}")
            if state["forward_privacy_mode"] != self.forward_privacy_mode:
                raise ValueError(
                    f"State was exported in mode {state['forward_privacy_mode']!r}, "
                    f"this instance uses {self.forward_privacy_mode!r}"
                )
            if not hmac.compare_digest(str(state["key_check"]), self._key_check()):
                raise ValueError("State was exported under different keys")

            update_count = state["update_count"]
            if isinstance(update_count, bool) or not isinstance(update_count, int):
                raise TypeError("update_count must be an integer")

            keyword_state: dict[str, dict] = {}
            for kw, entry in state["keyword_state"].items():
                counter = entry["counter"]
                if isinstance(counter, bool) or not isinstance(counter, int) or counter < 0:
                    raise TypeError("counter must be a non-negative integer")
                keyword_state[str(kw)] = {
                    "initial": _b64decode(entry["initial"], _CHAIN_STATE_SIZE),
                    "current": _b64decode(entry["current"], _CHAIN_STATE_SIZE),
                    "counter": counter,
                }
            secure_index = {
                str(token): {str(doc_id) for doc_id in ids}
                for token, ids in state["secure_index"].items()
            }
            auxiliary_index = {
                str(tag): _b64decode(entry) for tag, entry in state["auxiliary_index"].items()
            }
            documents = {str(doc_id): _b64decode(doc) for doc_id, doc in state["documents"].items()}
        except (KeyError, TypeError, AttributeError, binascii.Error, UnicodeEncodeError) as exc:
            raise ValueError(f"Malformed forward-private SSE state: {exc}") from exc

        self._update_count = update_count
        self._keyword_state = keyword_state
        self._secure_index = secure_index
        self._auxiliary_index = auxiliary_index
        self._documents = documents


class BackwardPrivateIndex:
    """
    Keyword index with deletion support. Research prototype, not audited.

    This class does NOT provide backward privacy:
    - Deletes are addressed by plaintext doc_id and remove the token set the
      server already holds for that document, so the server learns exactly
      which tokens were deleted.
    - The delete tokens that delete_document() returns are not used for
      anything.
    - Plaintext keywords are kept in the same object as the server-side
      index.

    re_encrypt() rotates the search key and the delete key and rebuilds every
    token. It keeps the document encryption key of the wrapped
    SearchableEncryption, so documents encrypted earlier with ``self.sse``
    stay decryptable. Rotating the encryption key would mean re-encrypting
    those documents, which this class does not store.

    There is no garbage_collect(): the index and the keyword map are always
    changed together, so an orphaned index entry cannot occur and the earlier
    method could never find anything.

    Backward privacy as a security notion: Bost, Minaud and Ohrimenko,
    "Forward and Backward Private Searchable Encryption from Constrained
    Cryptographic Primitives", CCS 2017 (https://eprint.iacr.org/2017/805).
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
        Delete a document from the index.

        Not backward-private: removing doc_id's entry removes the exact token
        set the server already holds, so the deletion is fully visible. The
        returned delete tokens are derived from a separate key but are not
        used by this class.

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
        Rebuild every token under a fresh search key and delete key.

        The tokens are recomputed from the plaintext keywords held in this
        object, so previous search tokens and delete tokens stop matching.
        The document encryption key is kept: documents encrypted earlier with
        ``self.sse`` still decrypt with the new ``self.sse``.
        """
        new_sse = SearchableEncryption(self.sse.encryption_key, os.urandom(32))

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
