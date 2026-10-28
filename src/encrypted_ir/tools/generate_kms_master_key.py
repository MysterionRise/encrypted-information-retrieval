"""Generate a KMS-wrapped Encrypted IR app master key.

KMS ``GenerateDataKey`` creates the 256-bit key inside KMS and returns it wrapped under the
customer master key (CMK); only the wrapped copy is printed, and the plaintext is discarded
here. The key is bound to the KMS encryption context for ``--environment`` (application,
environment and purpose), which the API uses again to unwrap it at startup, so a key generated
for one environment does not unwrap in another.

Rotate the CMK on the KMS side (automatic key rotation, or a new key version): KMS keeps
older versions to decrypt existing ciphertexts, so the wrapped master key keeps working and
nothing in this repository has to re-wrap it (ADR-018).
"""

from __future__ import annotations

import argparse
import base64

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

    provider = AWSKMSProvider(
        args.kms_key_id,
        region=args.region,
        encryption_context=master_key_encryption_context(args.environment),
    )
    _, encrypted_master_key = provider.generate_data_key("AES_256")

    print(
        "ENCRYPTED_IR_ENCRYPTED_MASTER_KEY_B64="
        + base64.b64encode(encrypted_master_key).decode("ascii")
    )


if __name__ == "__main__":
    main()
