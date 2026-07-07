"""Generate a KMS-wrapped Encrypted IR app master key."""

from __future__ import annotations

import argparse
import base64
import os

from encrypted_ir.kms_provider import AWSKMSProvider


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kms-key-id", required=True, help="AWS KMS key ID, ARN, or alias")
    parser.add_argument("--region", default=None, help="AWS region")
    args = parser.parse_args()

    master_key = os.urandom(32)
    provider = AWSKMSProvider(args.kms_key_id, region=args.region)
    encrypted_master_key = provider.encrypt(master_key)

    print(
        "ENCRYPTED_IR_ENCRYPTED_MASTER_KEY_B64="
        + base64.b64encode(encrypted_master_key).decode("ascii")
    )


if __name__ == "__main__":
    main()
