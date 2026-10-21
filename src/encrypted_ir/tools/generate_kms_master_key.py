"""Generate a KMS-wrapped Encrypted IR app master key.

The key is wrapped with the KMS encryption context for ``--environment`` (application,
environment and purpose), which the API uses again to unwrap it at startup. A key generated
for one environment does not unwrap in another.
"""

from __future__ import annotations

import argparse
import base64
import os

from encrypted_ir.kms_provider import AWSKMSProvider
from encrypted_ir.master_key import master_key_encryption_context

ENVIRONMENTS = ("dev", "test", "prod")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kms-key-id", required=True, help="AWS KMS key ID, ARN, or alias")
    parser.add_argument("--region", default=None, help="AWS region")
    parser.add_argument(
        "--environment",
        choices=ENVIRONMENTS,
        default="prod",
        help="Value of ENCRYPTED_IR_ENV where the key will be used (default: prod)",
    )
    args = parser.parse_args(argv)

    master_key = os.urandom(32)
    provider = AWSKMSProvider(
        args.kms_key_id,
        region=args.region,
        encryption_context=master_key_encryption_context(args.environment),
    )
    encrypted_master_key = provider.encrypt(master_key)

    print(
        "ENCRYPTED_IR_ENCRYPTED_MASTER_KEY_B64="
        + base64.b64encode(encrypted_master_key).decode("ascii")
    )


if __name__ == "__main__":
    main()
