"""Route TLS verification through the macOS system trust store.

certifi no longer carries every Apple root that gsa.apple.com chains to
(the 2026 bundle has no Apple Root CA at all), so the stock requests
trust store rejects Apple's own certificate with "self-signed
certificate in certificate chain". macOS trusts that root through the
keychain, so on darwin the process switches verification to truststore,
which uses the same store as curl and Safari. Verification is never
disabled.
"""

from __future__ import annotations

import sys


def configure_system_trust() -> None:
    """Use the macOS keychain trust store for all TLS in this process."""
    if sys.platform != "darwin":
        return
    import truststore

    truststore.inject_into_ssl()
