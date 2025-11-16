"""
Searchable Encryption Module

Implements searchable symmetric encryption for keyword searches on encrypted documents.
Uses a token-based approach where search tokens are generated from keywords.

Use Case: Document management, email archival, customer service knowledge bases.
"""

import os
import hmac
import hashlib
from typing import Set, List, Union
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64


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

    def _extract_keywords(self, text: str) -> Set[str]:
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
        document: Union[str, bytes],
        auto_extract_keywords: bool = True,
        keywords: Set[str] = None,
    ) -> tuple[bytes, Set[str]]:
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
        cipher = Cipher(
            algorithms.AES(self.encryption_key), modes.GCM(iv), backend=default_backend()
        )
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

        cipher = Cipher(
            algorithms.AES(self.encryption_key), modes.GCM(iv, tag), backend=default_backend()
        )
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

    def search(self, query_token: str, document_tokens: Set[str]) -> bool:
        """
        Check if a document matches a search query.

        Args:
            query_token: Search token from generate_search_query()
            document_tokens: Set of tokens from encrypt_document()

        Returns:
            True if document contains the keyword, False otherwise
        """
        return query_token in document_tokens

    def encrypt_document_to_base64(
        self,
        document: Union[str, bytes],
        auto_extract_keywords: bool = True,
        keywords: Set[str] = None,
    ) -> tuple[str, List[str]]:
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
        return (base64.b64encode(encrypted_doc).decode("ascii"), sorted(list(tokens)))

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
    def import_keys(encryption_key_b64: str, search_key_b64: str) -> "SearchableEncryption":
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
