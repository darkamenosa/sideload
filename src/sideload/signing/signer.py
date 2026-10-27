"""Execution of code signing with correct nested ordering.

Two interchangeable backends behind one interface:

    KeychainSigner  preferred. Imports the Apple issued certificate and
                    the locally generated private key into the login
                    keychain (keychain.py), then signs each binary with
                    the system "codesign" CLI:
                        codesign --force --timestamp=none
                                 --sign "<identity>" --entitlements <plist> <path>
                    Resource sealing (_CodeSignature/CodeResources) is
                    produced by codesign automatically for the outer
                    bundle.

    LDIDSigner      fallback when keychain access is unavailable, using
                    the installed ldid binary (AGPL-3.0, invoked strictly
                    as a separate process; see DESIGN.md for licensing):
                        ldid -S<entitlements.plist> <binary>
                    This mirrors AltSign, which signs with an embedded
                    ldid (AltSign/Signing/ALTSigner.mm).

Signing order, verified from zsign (src/bundle.cpp SignNode) and
codesign requirements:

    1. every loose Mach-O (dylibs) inside any nested bundle
    2. framework binaries, deepest frameworks first
    3. each app extension executable, then the extension bundle root
    4. the main app executable LAST, because its signature seals
       Info.plist, embedded.mobileprovision, and all nested code

The common failure mode behind "invalid code signature" at install is
signing the outer bundle before the inner binaries or editing any file
after the outer signature; this module exists to prevent both.

Implementation note verified on macOS 26 codesign: sealing a bundle
DIRECTORY re-signs the executable inside it and strips the embedded
entitlements unless --entitlements is passed again, so every seal
carries the bundle's entitlement set.

Ownership: SIGN agent.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from collections.abc import Sequence
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID

from sideload.errors import SigningError, TransportError
from sideload.models import ProvisioningProfile, SigningIdentity
from sideload.signing.entitlements import (
    KEY_APPLICATION_IDENTIFIER,
    KEY_GET_TASK_ALLOW,
    KEY_KEYCHAIN_ACCESS_GROUPS,
    KEY_TEAM_IDENTIFIER,
    write_entitlements_plist,
)
from sideload.signing.ipa import AppBundle, has_code_signature

_COMMAND_TIMEOUT = 300.0

_HINT_CODESIGN_MISSING = (
    "codesign ships with Xcode; install it with: xcode-select --install"
)
_HINT_LDID_MISSING = "ldid is the fallback signer; install it with: brew install ldid"


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


def _run_command(command: Sequence[str]) -> subprocess.CompletedProcess[bytes]:
    """Run one signing tool with captured output (test seam)."""
    try:
        return subprocess.run(
            list(command), check=False, capture_output=True, timeout=_COMMAND_TIMEOUT
        )
    except FileNotFoundError as exc:
        raise TransportError(f"tool not found: {command[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise SigningError(f"tool timed out: {command[0]}") from exc
    except OSError as exc:
        raise SigningError(f"could not run {command[0]}: {exc}") from exc


def _relative_posix(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _write_entitlements_file(entitlements: dict[str, object]) -> Path:
    handle, name = tempfile.mkstemp(prefix="sideload-ents-", suffix=".plist")
    os.close(handle)
    path = Path(name)
    write_entitlements_plist(entitlements, path)
    return path


def _string_list(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [item for item in value if isinstance(item, str)]
    return []


class Signer:
    """Interface for a signing backend.

    The base class owns the signing ORDER; backends only implement how
    one path is signed and how a bundle directory is sealed.
    """

    def sign_bundle(
        self,
        bundle: AppBundle,
        entitlements_by_path: dict[str, dict[str, object]],
        identity: SigningIdentity,
    ) -> None:
        """Sign every Mach-O in the bundle in the pinned order.

        entitlements_by_path maps each binary path (relative to the
        bundle root) to the entitlement dict to embed; the bundle
        executable always gets the profile derived set.

        Raises SigningError with the tool's stderr captured verbatim.

        Order enforced here:
            1. loose dylibs, deepest first
            2. framework binaries, deepest first
            3. nested extension executables (deepest first), then the
               nested bundle roots (frameworks, then extensions)
            4. this bundle's executable last, then the bundle root seal
        """
        inventory = bundle.signable_inventory()
        for path in inventory:
            key = _relative_posix(path, bundle.root)
            self._sign_path(path, entitlements_by_path.get(key), identity)
        for nested in bundle.nested_bundles():
            key = _relative_posix(nested.executable, bundle.root)
            self._seal_bundle(
                nested, entitlements_by_path.get(key), identity
            )
        main_key = _relative_posix(bundle.executable, bundle.root)
        self._seal_bundle(bundle, entitlements_by_path.get(main_key), identity)

    def verify_bundle(self, bundle: AppBundle) -> list[str]:
        """Post-sign verification ("codesign --verify --deep --verbose=2"
        or "ldid -r"). Returns a list of problems; empty means valid.

        The portable baseline checks that every signable Mach-O now
        carries an LC_CODE_SIGNATURE load command; backends with a
        stronger verifier override this.
        """
        problems: list[str] = []
        for path in bundle.signable_inventory():
            if not has_code_signature(path):
                problems.append(
                    f"{_relative_posix(path, bundle.root)}: no code signature"
                )
        return problems

    # ------------------------------------------------ backend primitives

    def _sign_path(
        self,
        path: Path,
        entitlements: dict[str, object] | None,
        identity: SigningIdentity,
    ) -> None:
        raise SigningError(
            f"{type(self).__name__} does not implement binary signing"
        )

    def _seal_bundle(
        self,
        bundle: AppBundle,
        entitlements: dict[str, object] | None,
        identity: SigningIdentity,
    ) -> None:
        """Seal a bundle root so its resources land in CodeResources.

        The default (ldid) semantics sign the bundle executable; the
        codesign backend overrides this to sign the directory itself.
        """
        self._sign_path(bundle.executable, entitlements, identity)


class KeychainSigner(Signer):
    """Signs with the macOS "codesign" CLI and a keychain identity."""

    def __init__(self) -> None:
        """Resolve codesign path once; raise TransportError if absent."""
        codesign = _which_tool("codesign")
        if codesign is None:
            raise TransportError(
                "the codesign tool was not found", hint=_HINT_CODESIGN_MISSING
            )
        self._codesign = codesign

    def _sign_path(
        self,
        path: Path,
        entitlements: dict[str, object] | None,
        identity: SigningIdentity,
    ) -> None:
        if not identity.keychain_identity:
            raise SigningError(
                "SigningIdentity has no keychain identity; import the "
                "development certificate first (keychain.py)"
            )
        command = [
            self._codesign,
            "--force",
            "--timestamp=none",
            "--sign",
            identity.keychain_identity,
        ]
        entitlements_path: Path | None = None
        try:
            if entitlements is not None:
                entitlements_path = _write_entitlements_file(entitlements)
                command += ["--entitlements", str(entitlements_path)]
            command.append(str(path))
            result = _run_command(command)
        finally:
            if entitlements_path is not None:
                entitlements_path.unlink(missing_ok=True)
        if result.returncode != 0:
            detail = result.stderr.decode("utf-8", "replace").strip()
            raise SigningError(f"codesign failed for {path}: {detail}")

    def _seal_bundle(
        self,
        bundle: AppBundle,
        entitlements: dict[str, object] | None,
        identity: SigningIdentity,
    ) -> None:
        # Signing the directory seals _CodeSignature/CodeResources and
        # re-signs the executable inside; entitlements must be re-passed
        # or codesign strips them (verified on macOS 26).
        self._sign_path(bundle.root, entitlements, identity)

    def verify_bundle(self, bundle: AppBundle) -> list[str]:
        problems = super().verify_bundle(bundle)
        if problems:
            return problems
        result = _run_command(
            [
                self._codesign,
                "--verify",
                "--deep",
                "--verbose=2",
                str(bundle.root),
            ]
        )
        if result.returncode == 0:
            return []
        lines = [
            line
            for line in result.stderr.decode("utf-8", "replace").splitlines()
            if line.strip()
        ]
        return lines or [f"codesign verification failed for {bundle.root}"]


class LDIDSigner(Signer):
    """Signs with the ldid binary from PEM key material directly.

    Used when the user refuses keychain access. Entitlements are
    injected per binary with -S<file>. The Homebrew ldid formula signs
    pseudo-signatures and cannot seal CodeResources, so verify_bundle
    falls back to the portable LC_CODE_SIGNATURE check; the identity's
    PEM material is retained for ldid builds that accept a signing key.
    """

    def __init__(self, identity: SigningIdentity) -> None:
        """Resolve ldid path once; raise TransportError if absent."""
        ldid = _which_tool("ldid")
        if ldid is None:
            raise TransportError("the ldid tool was not found", hint=_HINT_LDID_MISSING)
        self._ldid = ldid
        self.identity = identity

    def _sign_path(
        self,
        path: Path,
        entitlements: dict[str, object] | None,
        identity: SigningIdentity,
    ) -> None:
        command = [self._ldid, "-S"]
        entitlements_path: Path | None = None
        try:
            if entitlements is not None:
                entitlements_path = _write_entitlements_file(entitlements)
                command = [self._ldid, f"-S{entitlements_path}"]
            command.append(str(path))
            result = _run_command(command)
        finally:
            if entitlements_path is not None:
                entitlements_path.unlink(missing_ok=True)
        if result.returncode != 0:
            detail = result.stderr.decode("utf-8", "replace").strip()
            raise SigningError(f"ldid failed for {path}: {detail}")


def identity_name_for(certificate_pem: bytes) -> str:
    """Derive the codesign identity display name from the issued
    certificate, matching what "security find-identity -v" prints, for
    example "Apple Development: user@example.com (TEAMID)".
    """
    try:
        certificate = x509.load_pem_x509_certificate(certificate_pem)
    except ValueError as exc:
        raise SigningError(f"could not parse the signing certificate: {exc}") from exc
    common_names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    for name in common_names:
        if isinstance(name.value, str) and name.value:
            return name.value
    return certificate.subject.rfc4514_string()


def entitlements_ok_for_profile(
    entitlements: dict[str, object],
    profile: ProvisioningProfile,
) -> bool:
    """True when every embedded entitlement key is granted by the
    profile; used before install to predict signature rejection.
    """
    granted: dict[str, object] = dict(profile.entitlements)

    expected_application_id = granted.get(KEY_APPLICATION_IDENTIFIER)
    if not isinstance(expected_application_id, str) or not expected_application_id:
        expected_application_id = (
            f"{profile.team_identifier}.{profile.bundle_identifier}"
        )
    if entitlements.get(KEY_APPLICATION_IDENTIFIER) != expected_application_id:
        return False

    expected_team = _string_list(granted.get(KEY_TEAM_IDENTIFIER))
    if not expected_team:
        expected_team = [profile.team_identifier]
    actual_team = _string_list(entitlements.get(KEY_TEAM_IDENTIFIER))
    if not actual_team or sorted(actual_team) != sorted(expected_team):
        return False

    groups = _string_list(entitlements.get(KEY_KEYCHAIN_ACCESS_GROUPS))
    if groups:
        allowed = _string_list(granted.get(KEY_KEYCHAIN_ACCESS_GROUPS))
        if any(group not in allowed for group in groups):
            return False

    for key in entitlements:
        if key in (
            KEY_APPLICATION_IDENTIFIER,
            KEY_TEAM_IDENTIFIER,
            KEY_GET_TASK_ALLOW,
            KEY_KEYCHAIN_ACCESS_GROUPS,
        ):
            continue
        if key not in granted:
            return False
        granted_value = granted[key]
        if isinstance(granted_value, bool) and not granted_value:
            return False
    return True
