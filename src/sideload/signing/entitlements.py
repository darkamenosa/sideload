"""Entitlement extraction, merging, and validation.

How AltSign handles entitlements (verified in
AltSign/Signing/ALTSigner.mm) and what sideload pins:

    1. The provisioning profile ships an "Entitlements" dict. For free
       accounts it is small: application-identifier (TEAMID.bundle),
       get-task-allow (true), com.apple.developer.team-identifier.
       That dict is the base
       entitlement set for every binary in the bundle.
    2. The app binary may already carry entitlements (readable with
       "codesign -d --entitlements :- <binary>" or "ldid -e"). Keys the
       profile does not grant are DROPPED with a warning: installing a
       binary whose entitlements exceed the profile is the classic
       cause of an app installing fine and then being killed at launch
       by amfid ("invalid entitlements" SIGKILL). "com.apple.private.*"
       entitlements are never granted by free or standard paid
       profiles; tools needing them will not launch on a stock device.
    3. AltSign also merges "psychic paper" entitlements hidden in XML
       comments in the original entitlements blob; sideload extracts
       the same comment range "<!---><!-->" to "<!-- -->" when present.

Ownership: SIGN agent.
"""

from __future__ import annotations

import plistlib
import shutil
import subprocess
from pathlib import Path
from typing import Any
from xml.parsers.expat import ExpatError

from sideload.errors import EntitlementsError
from sideload.models import ProvisioningProfile

# Entitlement keys the resign pipeline always guarantees.
KEY_APPLICATION_IDENTIFIER = "application-identifier"
KEY_GET_TASK_ALLOW = "get-task-allow"
KEY_TEAM_IDENTIFIER = "com.apple.developer.team-identifier"
KEY_KEYCHAIN_ACCESS_GROUPS = "keychain-access-groups"

# Keys always rewritten from the profile so a re-signed binary can never
# keep the previous team's values (see DESIGN.md section 7).
_FORCED_KEYS = frozenset(
    {
        KEY_APPLICATION_IDENTIFIER,
        KEY_GET_TASK_ALLOW,
        KEY_TEAM_IDENTIFIER,
        KEY_KEYCHAIN_ACCESS_GROUPS,
    }
)

# Psychic paper markers (ALTSigner.mm): the hidden entitlement range is
# stored between these two XML comment fragments.
PSYCHIC_MARKER_START = "<!---><!-->"
PSYCHIC_MARKER_END = "<!-- -->"

_TOOL_TIMEOUT = 30.0


def _which_tool(name: str) -> str | None:
    """Resolve an external tool; config.find_tool once GLUE implements it."""
    try:
        from sideload import config

        resolved = config.find_tool(name)
        if resolved:
            return resolved
    except NotImplementedError:
        pass
    except ImportError:
        pass
    return shutil.which(name)


def _run_tool(command: list[str]) -> subprocess.CompletedProcess[bytes] | None:
    try:
        return subprocess.run(
            command, check=False, capture_output=True, timeout=_TOOL_TIMEOUT
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _raw_entitlements_blob(macho_path: Path) -> bytes | None:
    """The raw embedded entitlements XML, or None when absent.

    codesign prints an "Executable=" line ahead of the plist on stdout,
    so the plist is located by its XML declaration rather than parsed
    positionally.
    """
    blob: bytes | None = None
    codesign = _which_tool("codesign")
    if codesign is not None:
        result = _run_tool(
            [codesign, "-d", "--entitlements", ":-", str(macho_path)]
        )
        if result is not None and result.returncode == 0:
            blob = _first_xml_document(result.stdout)
    if blob is None:
        # codesign exits 0 with no plist for binaries it cannot classify
        # (ldid pseudo signatures); ldid can still dump those. ldid -e
        # prints the plist twice for some binaries, so only the first
        # complete document is kept.
        ldid = _which_tool("ldid")
        if ldid is not None:
            result = _run_tool([ldid, "-e", str(macho_path)])
            if result is not None and result.returncode == 0:
                blob = _first_xml_document(result.stdout)
    return blob


def _first_xml_document(output: bytes) -> bytes | None:
    """Slice the first complete XML plist out of a tool's stdout."""
    start = output.find(b"<?xml")
    if start < 0:
        return None
    end = output.find(b"</plist>", start)
    if end < 0:
        return output[start:]
    return output[start : end + len(b"</plist>")]


def read_entitlements(macho_path: Path) -> dict[str, object] | None:
    """Read the embedded entitlements of a signed Mach-O.

    Uses "codesign -d --entitlements :- <path>" first; falls back to
    "ldid -e" for pseudo signed or linker signed binaries that codesign
    refuses to dump. Returns None when the binary carries no
    entitlements or the blob cannot be parsed (psychic paper blobs are
    recovered separately by extract_commented_entitlements).
    """
    blob = _raw_entitlements_blob(macho_path)
    if blob is None:
        return None
    try:
        parsed: object = plistlib.loads(blob)
    except (plistlib.InvalidFileException, ExpatError, ValueError, IndexError):
        return None
    if isinstance(parsed, dict):
        return dict(parsed)
    return None


def extract_commented_entitlements(macho_path: Path) -> dict[str, object]:
    """Extract "psychic paper" entitlements hidden in XML comments
    inside the embedded entitlements blob (ALTSigner.mm behavior).
    """
    blob = _raw_entitlements_blob(macho_path)
    if blob is None:
        return {}
    text = blob.decode("utf-8", "replace")
    start = text.find(PSYCHIC_MARKER_START)
    if start < 0:
        return {}
    start += len(PSYCHIC_MARKER_START)
    end = text.find(PSYCHIC_MARKER_END, start)
    if end < 0:
        end = len(text)
    segment = text[start:end].strip()
    if not segment:
        return {}
    if "<plist" in segment:
        body = segment
    elif segment.startswith("<dict"):
        body = f'<plist version="1.0">{segment}</plist>'
    else:
        # Bare key/value children: plistlib requires a dict root.
        body = f'<plist version="1.0"><dict>{segment}</dict></plist>'
    try:
        parsed: object = plistlib.loads(body.encode("utf-8"))
    except (plistlib.InvalidFileException, ExpatError, ValueError, IndexError):
        return {}
    if isinstance(parsed, dict):
        return dict(parsed)
    return {}


def _is_granted(base: dict[str, object], key: str) -> bool:
    """A profile key with a False value is a disabled feature, not a grant."""
    if key not in base:
        return False
    value = base[key]
    return not (isinstance(value, bool) and not value)


def build_entitlements(
    profile: ProvisioningProfile,
    original: dict[str, object] | None,
    extra: dict[str, object] | None,
    strict: bool,
) -> tuple[dict[str, object], list[str]]:
    """Compute the entitlement set to embed for one bundle.

    Base is the profile Entitlements dict, then the app's own keys are
    merged only when the profile already grants them (a "true" valued
    profile key means the feature is available and the app's own
    parameters are kept). Keys the app requests that the profile does
    not grant are dropped (or, with strict=True, raise
    EntitlementsError).

    "extra" holds entitlements the caller explicitly vouches for, for
    example the psychic paper set from
    extract_commented_entitlements; they are merged without the
    profile check, mirroring AltSign.

    application-identifier, com.apple.developer.team-identifier, and
    keychain-access-groups are
    always stripped back to the team values from the profile, and
    get-task-allow is always true for development signing.

    Returns:
        (entitlements, dropped) where dropped lists requested keys that
        were removed. In strict mode any dropped key raises
        EntitlementsError instead.
    """
    base: dict[str, object] = dict(profile.entitlements)
    merged: dict[str, object] = dict(base)
    dropped: list[str] = []

    if original:
        for key, value in original.items():
            if key in _FORCED_KEYS:
                # These are rewritten from the profile below; the app's
                # own values must never survive a re-sign.
                continue
            if _is_granted(base, key):
                merged[key] = value
            else:
                dropped.append(key)

    if extra:
        merged.update(extra)

    application_identifier = base.get(KEY_APPLICATION_IDENTIFIER)
    if not isinstance(application_identifier, str) or not application_identifier:
        application_identifier = (
            f"{profile.team_identifier}.{profile.bundle_identifier}"
        )
    merged[KEY_APPLICATION_IDENTIFIER] = application_identifier
    merged[KEY_GET_TASK_ALLOW] = True

    # Apple profiles carry the team identifier as a string, and so must
    # the signature. Never keep the previous team's value.
    merged[KEY_TEAM_IDENTIFIER] = profile.team_identifier

    if KEY_KEYCHAIN_ACCESS_GROUPS in base:
        merged[KEY_KEYCHAIN_ACCESS_GROUPS] = base[KEY_KEYCHAIN_ACCESS_GROUPS]
    else:
        # Not granted: strip any copy (for example from "extra") and
        # count it as dropped when the app itself requested groups.
        merged.pop(KEY_KEYCHAIN_ACCESS_GROUPS, None)
        if original and KEY_KEYCHAIN_ACCESS_GROUPS in original:
            dropped.append(KEY_KEYCHAIN_ACCESS_GROUPS)

    dropped = sorted(set(dropped))
    if strict and dropped:
        raise EntitlementsError(
            "the app requests entitlements the profile does not grant: "
            + ", ".join(dropped),
            dropped=dropped,
            hint="sign again without --strict-entitlements to drop these "
            "keys with a warning, or use a profile that grants them",
        )
    return merged, dropped


def write_entitlements_plist(entitlements: dict[str, object], path: Path) -> None:
    """Serialize the entitlement dict as an XML plist for codesign.

    application-identifier and get-task-allow are always rewritten to
    match the profile (TEAMID.resigned-bundle-id and true respectively)
    by build_entitlements before this is called; this function writes
    the finished dict verbatim, sorted for deterministic output.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as handle:
        plistlib.dump(dict(entitlements), handle, fmt=plistlib.FMT_XML, sort_keys=True)


def validate_installable(
    profile: ProvisioningProfile,
    entitlements: dict[str, object],
) -> list[str]:
    """Return the list of entitlement keys that will make the device
    reject the install outright (for example a mismatched
    application-identifier). Empty list means the install should pass
    signature checks; runtime kill risk is separate (see DESIGN.md).
    """
    base: dict[str, Any] = dict(profile.entitlements)
    problems: list[str] = []

    expected_application_id = base.get(KEY_APPLICATION_IDENTIFIER)
    if not isinstance(expected_application_id, str) or not expected_application_id:
        expected_application_id = (
            f"{profile.team_identifier}.{profile.bundle_identifier}"
        )
    if entitlements.get(KEY_APPLICATION_IDENTIFIER) != expected_application_id:
        problems.append(KEY_APPLICATION_IDENTIFIER)

    expected_team = base.get(KEY_TEAM_IDENTIFIER)
    if not isinstance(expected_team, str) or not expected_team:
        expected_team = profile.team_identifier
    if entitlements.get(KEY_TEAM_IDENTIFIER) != expected_team:
        problems.append(KEY_TEAM_IDENTIFIER)

    groups = entitlements.get(KEY_KEYCHAIN_ACCESS_GROUPS)
    if groups is not None:
        allowed = _string_list(base.get(KEY_KEYCHAIN_ACCESS_GROUPS))
        requested = _string_list(groups)
        if any(group not in allowed for group in requested):
            problems.append(KEY_KEYCHAIN_ACCESS_GROUPS)

    return problems


def _string_list(value: object) -> list[str]:
    """Normalize a plist value that may be a string or a list of strings."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [item for item in value if isinstance(item, str)]
    return []

