"""Apple facing modules: authentication and developer services.

Module ownership inside this package:
    anisette.py   AUTH agent
    auth.py       AUTH agent (Grand Slam login and 2FA)
    developer.py  SIGN agent (teams, certificates, App IDs, profiles)

The boundary between them is AppleSession: auth.py produces it,
developer.py consumes it. Neither reads the other's internals.
"""

from __future__ import annotations
