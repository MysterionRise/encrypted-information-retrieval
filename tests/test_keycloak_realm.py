"""The demo Keycloak realm must issue tokens the API accepts (docs/OIDC_DEPLOYMENT.md).

scripts/oidc_smoke.sh proves it end to end; these checks catch a drifting realm file without
starting Keycloak.
"""

from __future__ import annotations

import json
from pathlib import Path

from encrypted_ir.api.dependencies.auth import Role
from encrypted_ir.settings import TENANT_ID_PATTERN

REALM_FILE = (
    Path(__file__).resolve().parent.parent / "deploy" / "keycloak" / "encrypted-ir-realm.json"
)
API_CLIENT = "encrypted-ir"
DEMO_CLIENT = "encrypted-ir-demo"


def _realm() -> dict:
    return json.loads(REALM_FILE.read_text())


def _demo_mappers() -> dict[str, dict]:
    [client] = [c for c in _realm()["clients"] if c["clientId"] == DEMO_CLIENT]
    return {m["config"].get("claim.name", m["name"]): m for m in client["protocolMappers"]}


def test_users_hold_only_api_roles_and_valid_tenants():
    realm = _realm()
    known_roles = {role.value for role in Role}
    defined = {r["name"] for r in realm["roles"]["client"][API_CLIENT]}
    assert defined <= known_roles

    tenants = set()
    for user in realm["users"]:
        assert set(user["clientRoles"][API_CLIENT]) <= known_roles, user["username"]
        assert set(user["clientRoles"]) == {API_CLIENT}, user["username"]
        assert "realmRoles" not in user, user["username"]
        [tenant] = user["attributes"]["tenant_id"]
        tenants.add(tenant)
    assert len(tenants) >= 2


def test_roles_claim_is_top_level_and_limited_to_the_api_client():
    roles = _demo_mappers()["roles"]
    config = roles["config"]

    # A realm-role mapper would add offline_access and default-roles-*, which the API rejects.
    assert roles["protocolMapper"] == "oidc-usermodel-client-role-mapper"
    assert config["usermodel.clientRoleMapping.clientId"] == API_CLIENT
    assert config["multivalued"] == "true"
    assert config["access.token.claim"] == "true"


def test_tenant_claim_and_audience_reach_the_access_token():
    mappers = _demo_mappers()
    assert mappers["tenant_id"]["config"]["user.attribute"] == "tenant_id"
    assert mappers["tenant_id"]["config"]["access.token.claim"] == "true"
    audience = next(m for m in mappers.values() if m["protocolMapper"] == "oidc-audience-mapper")
    assert audience["config"]["included.custom.audience"] == API_CLIENT
    assert audience["config"]["access.token.claim"] == "true"


def test_only_an_administrator_can_change_a_users_tenant():
    [provider] = _realm()["components"]["org.keycloak.userprofile.UserProfileProvider"]
    [profile_json] = provider["config"]["kc.user.profile.config"]
    profile = json.loads(profile_json)
    assert "unmanagedAttributePolicy" not in profile
    [tenant] = [a for a in profile["attributes"] if a["name"] == "tenant_id"]

    assert tenant["permissions"]["edit"] == ["admin"]
    assert tenant["validations"]["pattern"]["pattern"] == TENANT_ID_PATTERN
