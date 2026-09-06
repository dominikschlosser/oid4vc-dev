#!/usr/bin/env python3
"""Create a Keycloak offer and submit its query parameters to the wallet /credential-offer URL."""
import sys

import oid4vp_demo as demo


MEMBERSHIP_VCT = "https://credentials.example.com/membership"


def main():
    # Repeated demo runs would otherwise pile up membership credentials.
    removed = demo.delete_credentials_by_vct(MEMBERSHIP_VCT)
    if removed:
        print(f"0. Removed {removed} membership credential(s) from earlier runs")

    print(f"1. Creating a pre-authorized credential offer in {demo.KEYCLOAK_BASE_URL}/realms/{demo.ISSUER_REALM}")
    credential_offer = demo.create_credential_offer()

        # Use the wallet web endpoint with the same parameters as a custom URI offer.
    wallet_url = demo.offer_wallet_url(credential_offer)
    print("2. Invoking the wallet by URL:")
    print(f"   GET {wallet_url[:120]}...")
        # The wallet waits for consent. The helper approves through the API used by the UI.
    status, result = demo.invoke_wallet_interactively(lambda: demo.http_json(wallet_url))
    if status != 200:
        raise demo.DemoError(f"Wallet invocation failed ({status}): {result}")
    print("   Consent approved via the wallet's consent API.")
    print(f"   Wallet imported: format={result.get('format')} issuer={result.get('issuer')}")

    print("3. Credentials stored in the wallet:")
    credentials = demo.wallet_credentials()
    for credential in credentials:
        label = credential.get("vct") or credential.get("doctype") or credential.get("id")
        print(f"   - [{credential.get('format')}] {label}")

    if not any(c.get("vct") == MEMBERSHIP_VCT for c in credentials):
        raise demo.DemoError("Expected the membership credential to be stored in the wallet.")
    print()
    print("Success: credential issued via wallet URL, no custom scheme involved.")


if __name__ == "__main__":
    try:
        main()
    except demo.DemoError as err:
        print(err, file=sys.stderr)
        sys.exit(1)
