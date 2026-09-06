#!/usr/bin/env python3
"""Run an OIDC login against Keycloak and submit its wallet request to /authorize.

This adapts keycloak-verifier-oid4vp/scripts/login.py to use HTTP instead of the CLI."""
import sys
import tempfile

import oid4vp_demo as demo


def main():
    state = f"s-{demo.random_token(12)}"
    code_verifier = demo.random_pkce_verifier()
    code_challenge = demo.pkce_challenge(code_verifier)
    with tempfile.NamedTemporaryFile() as cookie_jar_file:
        cookie_jar = cookie_jar_file.name

        print(f"1. Starting login against {demo.KEYCLOAK_BASE_URL}/realms/{demo.VERIFIER_REALM}")
        print("2. Opening Keycloak's wallet login page")
        elements = demo.start_broker_login(cookie_jar, state, code_challenge)
        wallet_link = elements.get("oid4vp-open-wallet", {}).get("href")
        if not wallet_link:
            raise demo.DemoError("Could not find the same-device wallet link on the OID4VP broker page.")

        print("3. Invoking the wallet by URL instead of the custom scheme:")
        wallet_url = demo.to_wallet_web_url(wallet_link)
        print(f"   {wallet_link.split('?', 1)[0]}?... becomes {demo.WALLET_BASE_URL}/authorize?...")
                # The helper approves consent through the same API as the UI.
        redirect_uri = demo.invoke_wallet_interactively(lambda: demo.invoke_wallet_by_url(wallet_url))
        print("   Consent approved — wallet submitted the presentation.")

        print("4. Completing the broker flow in the original browser session")
        print("5. Exchanging the authorization code")
        id_token_claims = demo.complete_login(cookie_jar, redirect_uri, state, code_verifier)

        print()
        print("Success: presentation verified via wallet URL, no custom scheme involved.")
        if id_token_claims:
            print(f"   id_token.sub={id_token_claims.get('sub', '')}")
            preferred_username = id_token_claims.get("preferred_username", "")
            if preferred_username:
                print(f"   id_token.preferred_username={preferred_username}")


if __name__ == "__main__":
    try:
        main()
    except demo.DemoError as err:
        print(err, file=sys.stderr)
        sys.exit(1)
