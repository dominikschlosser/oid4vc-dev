#!/usr/bin/env python3
"""Configure Keycloak to use the wallet web URLs.

Set walletScheme to /authorize and trustListUrl to the wallet trust list. Derive both from WALLET_BASE_URL so port overrides also update the imported realm."""
import sys

import oid4vp_demo as demo


def update_idp(alias, auth, key, value):
    idp_url = f"{demo.KEYCLOAK_BASE_URL}/admin/realms/{demo.VERIFIER_REALM}/identity-provider/instances/{alias}"
    status, idp = demo.http_json(idp_url, headers=auth)
    if status != 200:
        raise demo.DemoError(f"Loading the {alias} identity provider failed ({status}): {idp}")
    idp["config"][key] = value
    status, result = demo.http_json(idp_url, json_data=idp, headers=auth, method="PUT")
    if status not in (200, 204):
        raise demo.DemoError(f"Updating the {alias} identity provider failed ({status}): {result}")


def main():
    status, token_response = demo.http_json(
        f"{demo.KEYCLOAK_BASE_URL}/realms/master/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": demo.KEYCLOAK_ADMIN_USER,
            "password": demo.KEYCLOAK_ADMIN_PASSWORD,
        },
    )
    if status != 200:
        raise demo.DemoError(f"Admin token request failed ({status}): {token_response}")
    auth = {"Authorization": f"Bearer {token_response['access_token']}"}

    wallet_base = demo.WALLET_BASE_URL.rstrip("/")
    wallet_scheme = f"{wallet_base}/authorize"
    trust_list_url = f"{wallet_base}/api/trustlist"
    update_idp("oid4vp", auth, "walletScheme", wallet_scheme)
    update_idp("demo-trust-list", auth, "trustListUrl", trust_list_url)
    print(f"walletScheme  = {wallet_scheme}")
    print(f"trustListUrl  = {trust_list_url}")


if __name__ == "__main__":
    try:
        main()
    except demo.DemoError as err:
        print(err, file=sys.stderr)
        sys.exit(1)
