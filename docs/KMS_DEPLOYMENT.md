# AWS KMS Deployment

How the app master key reaches the API in production, how to run that path on a laptop without
an AWS account, and the IAM and CloudTrail setup a real deployment needs.

## The key path

1. An operator runs `python -m encrypted_ir.tools.generate_kms_master_key`. KMS
   `GenerateDataKey` creates a 256-bit app master key inside KMS and returns it wrapped under the
   customer master key (CMK). Only the wrapped copy is printed.
2. The wrapped copy goes into `ENCRYPTED_IR_ENCRYPTED_MASTER_KEY_B64`. The API calls KMS
   `Decrypt` once at startup and keeps the master key in memory. Tenant keys are wrapped locally
   under it ([ADR-014](DECISIONS.md)).
3. Both calls carry the same encryption context:

   | Key | Value |
   | --- | --- |
   | `application` | `encrypted-information-retrieval` |
   | `environment` | the `ENCRYPTED_IR_ENV` the API runs under (`prod` in production) |
   | `purpose` | `app-master-key` |

   A key wrapped for one environment does not unwrap in another, and IAM can require the context
   (below).
4. Every successful unwrap writes a `key.unwrap` row to the `_system` audit chain.

Rotating the CMK happens in KMS (automatic key rotation). KMS keeps the older key material, so
the wrapped master key keeps working and nothing in this repository re-wraps it
([ADR-018](DECISIONS.md)). Tenant document and search keys rotate with
`python -m encrypted_ir.tools.rotate_tenant_keys` (README).

## Run it locally, without an AWS account

[moto server](https://github.com/getmoto/moto) stands in for AWS KMS in
[`docker-compose.kms.yml`](../docker-compose.kms.yml):

```bash
cp .env.example .env
./scripts/kms_smoke.sh
```

[`scripts/kms_smoke.sh`](../scripts/kms_smoke.sh) runs its own Compose project on a fresh volume
and removes it on exit (`KEEP_STACK=1` keeps it running). It:

1. creates a KMS key and the alias `alias/encrypted-ir-master` in moto, and wraps a dev master key
   with `generate_kms_master_key`
   ([`scripts/kms_bootstrap.py`](../scripts/kms_bootstrap.py));
2. starts the API with `ENCRYPTED_IR_KMS_PROVIDER=aws`;
3. ingests and retrieves a document, restarts the API, and retrieves it again;
4. checks that the `_system` audit chain verifies and holds exactly two `key.unwrap` rows, one per
   start (in dev mode `/ready` cannot tell a KMS key from a raw one);
5. starts the API with the same wrapped key and `ENCRYPTED_IR_ENV=test`, and checks that it fails
   with `InvalidCiphertextException`: the encryption context binds the key to its environment.

CI runs the same script in the `e2e` job. The production-mode run (`ENCRYPTED_IR_ENV=prod`, which
also needs an OIDC identity provider) is the subject of issue #48.

What this run does **not** show:

- **IAM.** moto does not enforce IAM, so the policies below are not exercised. Their shape is
  checked against the code by `tests/test_kms_iam_policy.py`, and that is all.
- **AWS itself.** moto implements the KMS API calls the API makes (`GenerateDataKey`, `Decrypt`)
  and binds the encryption context as authenticated data, so a wrong context fails as it does in
  AWS. It is still an emulator, not AWS.
- **Durability.** moto keeps keys in memory. Restarting or removing the moto container makes every
  master key wrapped under it undecryptable; bootstrap again after `docker compose down`.

The roadmap named LocalStack for this. Since LocalStack 2026.03.0 its image only starts with an
account auth token, which a reviewer without an account, or a CI run from a fork, does not have.
moto (Apache-2.0) needs neither.

## Production setup

1. Create a symmetric KMS key (`SYMMETRIC_DEFAULT`) and turn on automatic key rotation. Keep the
   default key policy, or any key policy that lets IAM policies in the account grant access:
   without that, the IAM policies below grant nothing.
2. Give the operator role [`docs/iam/kms-operator-policy.json`](iam/kms-operator-policy.json) and
   run, with that role:

   ```bash
   python -m encrypted_ir.tools.generate_kms_master_key \
     --kms-key-id arn:aws:kms:REGION:ACCOUNT_ID:key/KEY_ID --region REGION --environment prod
   ```

3. Give the API runtime role
   [`docs/iam/kms-api-runtime-policy.json`](iam/kms-api-runtime-policy.json) and set:

   | Setting | Value |
   | --- | --- |
   | `ENCRYPTED_IR_ENV` | `prod` |
   | `ENCRYPTED_IR_KMS_PROVIDER` | `aws` |
   | `ENCRYPTED_IR_AWS_KMS_KEY_ID` | the key ARN (or an alias of it) |
   | `AWS_REGION` | the key's region |
   | `ENCRYPTED_IR_ENCRYPTED_MASTER_KEY_B64` | the value the tool printed |

   `ENCRYPTED_IR_MASTER_KEY_B64` must not be set: prod refuses to start with it.
4. Check `/ready`: in prod, `checks.key_provider` is `true` only when the key came from KMS.

### IAM policies

| Role | File | Actions | Condition |
| --- | --- | --- | --- |
| API runtime | [`kms-api-runtime-policy.json`](iam/kms-api-runtime-policy.json) | `kms:Decrypt` | the encryption context above, with `environment=prod` |
| Operator | [`kms-operator-policy.json`](iam/kms-operator-policy.json) | `kms:GenerateDataKey` | the same encryption context |
| Operator | same file | `kms:DescribeKey` | none |

Notes:

- **The API needs `kms:Decrypt` and nothing else.** It never calls `GenerateDataKey` or
  `DescribeKey`.
- **Resources are key ARNs.** Replace `REGION`, `ACCOUNT_ID` and `KEY_ID`. An alias ARN does not
  match key operations in an IAM policy, even when the API is configured with the alias.
- **`kms:DescribeKey` has no context condition.** `DescribeKey` sends no encryption context, so
  such a condition would deny it every time.
- **Other environments.** For a `dev` or `test` deployment, copy the policies with that
  `environment` value.

### CloudTrail

This repository does not configure CloudTrail. The KMS calls above are recorded only if the
operator sets it up:

- KMS API calls (`Decrypt`, `GenerateDataKey`, `DescribeKey`) are CloudTrail **management events**.
- CloudTrail event history keeps 90 days of management events in each region, without a trail.
- For longer retention, create a trail that logs **read** management events (`Decrypt` is a read
  event) and does not exclude AWS KMS events. Send it to a bucket the API role cannot write.
- The API's own `key.unwrap` audit rows record each start. CloudTrail is the KMS-side record of
  the same calls, and of any call the API did not make.
