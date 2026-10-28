"""Create the demo KMS key in moto and print a master key wrapped under it.

Runs inside the API image (which has boto3), fed on stdin by scripts/kms_smoke.sh and
scripts/oidc_smoke.sh:

    docker compose run --rm -T kms-init --environment dev < scripts/kms_bootstrap.py

Idempotent: if the alias already exists, its key is reused, so dev and prod master keys can be
wrapped under the same key in one moto session. The wrapped key itself comes from the shipped
tool, encrypted_ir.tools.generate_kms_master_key (GenerateDataKey with the environment's
encryption context), whose one output line is the only thing written to stdout.
"""

from __future__ import annotations

import argparse
import sys

import boto3

from encrypted_ir.tools import generate_kms_master_key

ALIAS = "alias/encrypted-ir-master"
REGION = "us-east-1"


def ensure_key(client) -> str:
    """Return the ID of the key behind ``ALIAS``, creating both if needed."""
    for alias in client.list_aliases()["Aliases"]:
        if alias["AliasName"] == ALIAS and alias.get("TargetKeyId"):
            return alias["TargetKeyId"]
    key_id = client.create_key(
        Description="Encrypted IR demo master-key CMK (moto)",
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
    )["KeyMetadata"]["KeyId"]
    client.create_alias(AliasName=ALIAS, TargetKeyId=key_id)
    return key_id


def main(argv: list[str]) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--environment", required=True, choices=("dev", "test", "prod"))
    args = parser.parse_args(argv)

    key_id = ensure_key(boto3.client("kms", region_name=REGION))
    print(f"kms key {key_id} ({ALIAS})", file=sys.stderr)
    generate_kms_master_key.main(
        ["--kms-key-id", ALIAS, "--region", REGION, "--environment", args.environment]
    )


if __name__ == "__main__":
    main(sys.argv[1:])
