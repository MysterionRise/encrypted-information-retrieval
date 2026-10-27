"""Research prototypes. Not audited and not used by the durable document path.

Importing this package issues a :class:`~encrypted_ir.errors.ResearchPrototypeWarning`.
Import the submodules directly, for example ``from encrypted_ir.research.ore import ORE``:

- ``ore``: CLWW-style order-revealing encryption. Comparison needs no key, so ciphertexts
  reveal their total order.
- ``fpe``: NIST SP 800-38G FF1 format-preserving encryption.
- ``homomorphic``: CKKS via TenSEAL (needs the ``research`` extra).
- ``post_quantum``: ML-KEM, ML-DSA and a hybrid KEM via pqcrypto (needs the ``research`` extra).
- ``differential_privacy``: Laplace, Gaussian and exponential mechanisms with a budget tracker.
- ``forward_private_sse``: a hash-chain forward-private SSE and a deletable keyword index.
- ``use_cases``: financial-services demos built from the primitives above.

Known defects are tracked in issue #38. docs/THREAT_MODEL.md lists the leakage of each one.
"""

from __future__ import annotations

import warnings

from ..errors import ResearchPrototypeWarning

warnings.warn(
    "encrypted_ir.research contains unaudited cryptographic prototypes that are not used by the "
    "durable document path. Do not use them to protect real data. See docs/THREAT_MODEL.md.",
    ResearchPrototypeWarning,
    stacklevel=2,
)

__all__ = [
    "differential_privacy",
    "forward_private_sse",
    "fpe",
    "homomorphic",
    "ore",
    "post_quantum",
    "use_cases",
]
