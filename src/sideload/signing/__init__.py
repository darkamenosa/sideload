"""IPA resigning pipeline.

Module ownership inside this package (all SIGN agent):
    csr.py          keypair and CSR generation for submitDevelopmentCSR
    profile.py      .mobileprovision parsing and validation
    entitlements.py entitlement extraction, merging, and validation
    ipa.py          IPA extraction, bundle inventory, repack
    signer.py       codesign/ldid execution with correct nested order
"""

from __future__ import annotations
