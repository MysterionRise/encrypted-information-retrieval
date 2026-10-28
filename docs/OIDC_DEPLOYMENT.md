# OIDC Deployment

How the API authenticates callers in production, how to run that path on a laptop with Keycloak,
and how to map the claims of four common identity providers.

## What the API accepts

In production (`ENCRYPTED_IR_ENV=prod`) every request needs an `Authorization: Bearer` access
token. The API verifies it against the identity provider's JWKS
(`src/encrypted_ir/api/dependencies/auth.py`):

| Rule | Detail |
| --- | --- |
| Signature | `RS256` by default; `ENCRYPTED_IR_OIDC_ALGORITHMS` may allow `PS256` and `ES256`, nothing else. The key is chosen by the token's `kid` from `ENCRYPTED_IR_OIDC_JWKS_URL`. |
| Required claims | `iss`, `aud`, `exp` and `iat`. `nbf` is checked when present. Clock leeway is `ENCRYPTED_IR_JWT_LEEWAY_SECONDS` (default 30). |
| `iss` | Must equal `ENCRYPTED_IR_OIDC_ISSUER` exactly, byte for byte, including any trailing slash. |
| `aud` | A string, or a list that contains `ENCRYPTED_IR_OIDC_AUDIENCE`. |
| Tenant | The claim named by `ENCRYPTED_IR_TENANT_CLAIM` (default `tenant_id`): a string matching `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`. |
| Roles | The claim named by `ENCRYPTED_IR_ROLES_CLAIM` (default `roles`): a non-empty list of strings, or a space-separated string. |

Two rules catch most misconfigurations:

- **Claims are read at the top level of the token only.** A nested claim such as Keycloak's
  `realm_access.roles` is not found. Point the setting at a top-level claim, or add a mapper that
  emits one.
- **Every role value must be `read`, `write` or `admin`.** Any other value in the roles claim,
  such as an unrelated group, makes the request fail with 403. Emit only the API's roles in that
  claim.

| Role | Allows |
| --- | --- |
| `read` | search, get one document, RAG retrieve |
| `write` | everything `read` allows, plus ingest and delete |
| `admin` | everything `write` allows |

A document of another tenant answers 404 to get and delete, and is absent from search and
retrieval results. Dev auth (the `X-API-Key` header and HS256 dev tokens) is refused outside
`ENCRYPTED_IR_ENV=dev`.

## Run it locally, without a cloud account

[`docker-compose.oidc.yml`](../docker-compose.oidc.yml) adds Keycloak 26 with the realm in
[`deploy/keycloak/encrypted-ir-realm.json`](../deploy/keycloak/encrypted-ir-realm.json) and runs
the API in `ENCRYPTED_IR_ENV=prod`. Prod also needs KMS, so the file is layered on
[`docker-compose.kms.yml`](../docker-compose.kms.yml) (moto server as the KMS emulator, see
[KMS_DEPLOYMENT.md](KMS_DEPLOYMENT.md)):

```bash
cp .env.example .env
./scripts/oidc_smoke.sh
```

The realm defines:

| User | `tenant_id` | Roles |
| --- | --- | --- |
| `alice` | `tenant-a` | `read`, `write` |
| `carol` | `tenant-a` | `read` |
| `bob` | `tenant-b` | `read`, `write` |

- **Roles** are client roles of the `encrypted-ir` client, emitted as a top-level `roles` array by
  a client-role mapper. Realm roles never reach the claim.
- **`tenant_id`** is a user-profile attribute that only an administrator can edit.
- **The caller** is the confidential client `encrypted-ir-demo`. It uses the password grant,
  which is acceptable for this local demo only: OAuth 2.0 security best current practice
  (RFC 9700) says it must not be used.
- **Demo values.** The client secret and the passwords (`<user>-demo-password`) are committed,
  public demo values.
- **Issuer.** `KC_HOSTNAME` fixes the issuer at `http://keycloak:8080/realms/encrypted-ir`, so
  tokens fetched through `localhost:8080` carry the issuer the API expects.

[`scripts/oidc_smoke.sh`](../scripts/oidc_smoke.sh):

1. checks that the API's environment has no raw master key and no dev auth;
2. starts it in prod, and waits until `/ready` reports every check true;
3. fetches RS256 tokens and checks their `iss`, `aud`, `tenant_id` and `roles` claims;
4. checks the responses:

   | Caller | Request | Expected |
   | --- | --- | --- |
   | alice | ingest | 200 |
   | alice | retrieve | 200, document found |
   | bob | get, delete | 404 |
   | bob | retrieve | document absent |
   | carol | ingest | 403 |
   | carol | retrieve | 200, document found |
   | token with a broken signature | retrieve | 401 |
   | the dev API key | retrieve | 401 |

5. restarts the API, retrieves again as alice, and verifies tenant-a's audit chain.

CI runs it in the `e2e` job.

What this run does not show: a real identity provider's token formats. The table below comes from
vendor documentation and has not been run against a real tenant of any of the four.

## Claim mapping for real identity providers

In every case, the access token must be issued for this API (its own audience), not for the
identity provider's own APIs.

| Identity provider | `ENCRYPTED_IR_OIDC_ISSUER` | `ENCRYPTED_IR_OIDC_AUDIENCE` | `ENCRYPTED_IR_OIDC_JWKS_URL` | Tenant claim | Roles claim |
| --- | --- | --- | --- | --- | --- |
| Amazon Cognito | `https://cognito-idp.<region>.amazonaws.com/<user-pool-id>` | the app client ID | `<issuer>/.well-known/jwks.json` | `tenant_id`, added by the trigger | `roles`, added by the trigger |
| Auth0 | `https://<tenant>.auth0.com/` (trailing slash) | the API identifier | `https://<tenant>.auth0.com/.well-known/jwks.json` | `https://<your-namespace>/tenant_id` | `https://<your-namespace>/roles` |
| Okta (custom authorization server) | `https://<okta-domain>/oauth2/<server-id>` | the server's audience (for example `api://default`) | `<issuer>/v1/keys` | `tenant_id` | `roles` |
| Microsoft Entra ID (v2.0 tokens) | `https://login.microsoftonline.com/<directory-id>/v2.0` | the API's application (client) ID | `https://login.microsoftonline.com/<directory-id>/discovery/v2.0/keys` | see below | `roles` (app roles) |

What each needs:

- **Amazon Cognito.**
  - Cognito access tokens carry `client_id`, not `aud`, so they fail this API's `aud` check as
    issued.
  - A pre token generation Lambda trigger with event version 2 or later (user pools on the
    Essentials or Plus feature plan) can add:
    - `aud`, whose value must be the app client ID;
    - a `tenant_id` claim, for example from a custom attribute;
    - a `roles` array.
  - Do not point the roles claim at `cognito:groups` unless users belong to no other groups:
    any other group name means 403.
- **Auth0.**
  - Access tokens for an Auth0 API audience cannot carry custom claims without a namespace, and
    `roles` is a reserved name.
  - Add namespaced claims in a post-login Action with `api.accessToken.setCustomClaim`, using the
    RBAC roles named `read`, `write` and `admin`.
  - Set `ENCRYPTED_IR_TENANT_CLAIM` and `ENCRYPTED_IR_ROLES_CLAIM` to the full namespaced names.
  - `aud` may be a list that also contains the `/userinfo` URL; the API accepts that.
- **Okta.**
  - Use a custom authorization server. The org authorization server cannot put a groups claim in
    access tokens. Custom servers need API Access Management in production orgs.
  - Add a `tenant_id` claim from a profile attribute (expression `user.tenant_id`).
  - Add a groups claim named `roles`, with a filter that matches only the groups `read`, `write`
    and `admin` (for example the regex `^(read|write|admin)$`).
- **Microsoft Entra ID.**
  - Set the API's `accessTokenAcceptedVersion` to 2. Define app roles with the values `read`,
    `write` and `admin`, and assign them; they arrive in the top-level `roles` claim.
  - The tenant: if every customer is its own Entra directory, `ENCRYPTED_IR_TENANT_CLAIM=tid`
    works (a directory GUID matches the tenant pattern). Otherwise emit a directory extension
    attribute as an optional claim, and set the tenant claim to its full name
    (`extension_<app-id>_tenant_id`).
  - A multi-tenant app sees one issuer per directory. This API accepts exactly one issuer, so it
    serves one directory per deployment.
