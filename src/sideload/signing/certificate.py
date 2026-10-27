"""Certificate based signing: an existing developer certificate plus
provisioning profile instead of an Apple ID login.

This is the path Sideloadly offers as certificate signing: the user
already owns a signing identity (an exported .p12 holding the
certificate and the private key) and a .mobileprovision that lists
that certificate, the bundle id, and the target devices. Nothing in
this module talks to Apple: no Grand Slam login, no anisette, no
developerservices2 action, no App ID creation, no team fetch, and no
Keychain session. The flow:

    1. validate the three input files (IPA, .p12, .mobileprovision);
       usage failures happen before anything prompts or mutates
    2. parse the profile with the real "security cms" path
       (signing/profile.py)
    3. extract the IPA and resolve the bundle id to sign: the profile
       application-identifier decides it, --bundle-id may only agree,
       a wildcard profile (TEAMID.*) keeps the original id
    4. validate the profile with assert_profile_usable: expiry, the
       targeted device, the bundle id, and that a developer
       certificate is listed; then fail early when one specific
       profile cannot cover the app extensions
    5. read the .p12 passphrase with getpass (never argv, never
       persisted, never logged) and unlock the p12 locally first, so
       a wrong passphrase fails before any Keychain change
    6. import the p12 into the login Keychain trusted for
       /usr/bin/codesign only (keychain.import_identity reuses
       "security import -T /usr/bin/codesign" with the passphrase fed
       on stdin) and keep the returned codesign identity name; modern
       AES p12s are re-wrapped locally when security refuses the
       format
    7. rewrite Info.plist bundle ids, embed the profile, build
       entitlements from it (strict mode honored), sign nested
       bundles deepest first, and repack through signing/ipa.py

Ownership: SIGN agent. Reuses keychain.py, signing/profile.py,
signing/entitlements.py, signing/ipa.py, and signing/signer.py.
"""

from __future__ import annotations

import getpass
import os
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import pkcs12

from sideload import errors
from sideload import keychain as keychain_mod
from sideload.models import ProvisioningProfile, SigningIdentity
from sideload.signing import entitlements as entitlements_mod
from sideload.signing import ipa as ipa_mod
from sideload.signing import profile as profile_mod
from sideload.signing import signer as signer_mod

# The bundle id of a wildcard profile (application-identifier TEAMID.*).
WILDCARD_BUNDLE_ID: Final[str] = "*"

# A caller that produces the .p12 passphrase; the default reads it with
# getpass so it never enters argv, a log, or persistent storage.
PassphraseProvider = Callable[[Path], str]


@dataclass(frozen=True)
class CertificateSignOutcome:
    """Everything the certificate pipeline produced for one IPA."""

    output_ipa: str
    original_bundle_id: str
    signed_bundle_id: str
    profile: ProvisioningProfile
    identity: SigningIdentity


def read_p12_passphrase(p12_path: Path) -> str:
    """Read the .p12 passphrase interactively with getpass.

    getpass never echoes; the passphrase lives in process memory only,
    reaches the security CLI on stdin, and is never written to disk,
    argv, or output. A missing terminal is a usage error rather than a
    silently accepted empty passphrase.
    """
    try:
        return getpass.getpass(f"p12 passphrase for {p12_path.name}: ")
    except EOFError:
        raise errors.UsageError(
            "could not read the p12 passphrase; run from a terminal"
        ) from None


def _normalize_dt(value: datetime) -> datetime:
    """Assume UTC for naive datetimes (profile plists carry UTC)."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


def _format_datetime(value: datetime) -> str:
    return _normalize_dt(value).strftime("%Y-%m-%d %H:%M:%S %Z")


@dataclass(frozen=True)
class UnlockedIdentity:
    """The p12 contents after a successful local unlock."""

    private_key: pkcs12.PKCS12PrivateKeyTypes
    certificate: x509.Certificate
    chain: list[x509.Certificate]


def _unlock_p12(data: bytes, passphrase: str, p12_path: Path) -> UnlockedIdentity:
    """Open the p12 locally so a wrong passphrase fails before any
    Keychain change. Returns the key, the signing certificate, and the
    intermediate chain carried inside the file.
    """
    # An empty input means the user pressed enter; None is what an
    # unencrypted p12 expects, and a wrong password still raises.
    password: bytes | None = passphrase.encode("utf-8") if passphrase else None
    try:
        private_key, certificate, cas = pkcs12.load_key_and_certificates(
            data, password
        )
    except ValueError as exc:
        raise errors.SigningError(
            f"could not unlock {p12_path.name}: the passphrase is wrong "
            "or the file is not a .p12",
            hint="export the certificate and private key again (Keychain "
            "Access or Xcode) and retry",
        ) from exc
    if certificate is None:
        raise errors.SigningError(f"{p12_path.name} contains no certificate")
    if private_key is None:
        raise errors.SigningError(
            f"{p12_path.name} contains no private key, so it cannot be "
            "used for code signing",
            hint="export the certificate with its private key from "
            "Keychain Access (the .p12 item), not the certificate alone",
        )
    if not isinstance(
        private_key,
        (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey),
    ):
        raise errors.SigningError(
            f"{p12_path.name} holds a private key that cannot be used "
            "for code signing"
        )
    return UnlockedIdentity(
        private_key=private_key,
        certificate=certificate,
        chain=list(cas) if cas else [],
    )


def _legacy_p12_encryption(passphrase: str) -> serialization.KeySerializationEncryption:
    """The p12 wrapping Apple's security CLI accepts.

    "security import" (SecKeychainItemImport) rejects the modern p12
    format (AES plus a SHA-256 MAC, what OpenSSL 3 and most non Apple
    tools export now) with "MAC verification failed" or "Unknown
    format" even when the passphrase is correct. The legacy wrapping,
    PBE-SHA1-3DES with a SHA-1 MAC (verified live against security
    import), is accepted. The weakness of the legacy ciphers is not a
    concern here: the re-wrapped file lives for seconds as a 0600
    per-user temp file and is deleted right after the import.
    """
    return (
        serialization.PrivateFormat.PKCS12.encryption_builder()
        .kdf_rounds(50000)
        .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
        .hmac_hash(hashes.SHA1())
        .build(passphrase.encode("utf-8"))
    )


def _import_identity(
    keychain: keychain_mod.KeychainStore,
    p12_path: Path,
    passphrase: str,
    team_identifier: str,
    identity_material: UnlockedIdentity,
) -> str:
    """Import the p12 into the login Keychain trusted for
    /usr/bin/codesign and return the codesign identity name.

    Modern-format p12s (AES plus SHA-256 MAC) are re-wrapped locally
    into the legacy form security import accepts when the direct
    import is refused on format grounds. The passphrase never changes
    and never leaves memory or the security CLI's stdin.
    """
    try:
        return keychain.import_identity(str(p12_path), passphrase, team_identifier)
    except errors.KeychainError as exc:
        message = exc.message
        if "MAC verification" not in message and "Unknown format" not in message:
            raise
    legacy = _legacy_p12_encryption(passphrase)
    data = pkcs12.serialize_key_and_certificates(
        name=b"sideload",
        key=identity_material.private_key,
        cert=identity_material.certificate,
        cas=identity_material.chain or None,
        encryption_algorithm=legacy,
    )
    fd, temp_name = tempfile.mkstemp(prefix="sideload-identity-", suffix=".p12")
    os.close(fd)
    temp_path = Path(temp_name)
    try:
        temp_path.write_bytes(data)
        os.chmod(temp_path, 0o600)
        print(
            f"note: {p12_path.name} uses a p12 wrapping the macOS "
            "Keychain cannot import; re-wrapped it locally and imported the copy"
        )
        return keychain.import_identity(str(temp_path), passphrase, team_identifier)
    finally:
        temp_path.unlink(missing_ok=True)


def _resolve_bundle_id(
    profile: ProvisioningProfile,
    bundle_id_override: str | None,
    original_bundle_id: str,
) -> tuple[str, str]:
    """The bundle id to sign, and the id to validate the profile with.

    A specific profile pins the id: --bundle-id must agree with it or
    the run is a usage error. A wildcard profile (application-identifier
    TEAMID.*) signs any id: --bundle-id wins, then the original id.
    The validation id is what assert_profile_usable compares against
    the profile: the target id, or the wildcard marker itself.
    """
    if profile.bundle_identifier == WILDCARD_BUNDLE_ID:
        target = bundle_id_override or original_bundle_id
        if not target:
            raise errors.IPAError(
                "the app has no CFBundleIdentifier and the wildcard "
                "profile does not name one",
                hint="pass --bundle-id to pick the bundle id to sign",
            )
        return target, profile.bundle_identifier
    if bundle_id_override is not None and bundle_id_override != profile.bundle_identifier:
        raise errors.UsageError(
            f"--bundle-id {bundle_id_override} conflicts with the profile, "
            f"which provisions {profile.bundle_identifier}",
            hint="drop --bundle-id to sign as the profile bundle id, or "
            "pass a profile that provisions it",
        )
    return profile.bundle_identifier, profile.bundle_identifier


def _bundle_list(ipa_bundle: ipa_mod.IPABundle) -> list[ipa_mod.AppBundle]:
    """Main bundle first, then every nested bundle (the same inventory
    order the Apple ID pipeline signs)."""
    bundles = list(ipa_bundle.all_bundles)
    if ipa_bundle.main_bundle not in bundles:
        bundles.insert(0, ipa_bundle.main_bundle)
    return bundles


def _check_extensions(
    profile: ProvisioningProfile,
    bundles: list[ipa_mod.AppBundle],
    main_bundle: ipa_mod.AppBundle,
    original_bundle_id: str,
    signed_bundle_id: str,
) -> None:
    """One profile must cover every extension or the run fails before
    signing: a specific application-identifier never covers a child
    bundle id, only a wildcard profile does. A single profile cannot be
    split per extension the way the Apple ID flow downloads one
    profile per App ID.
    """
    extensions = [
        bundle
        for bundle in bundles
        if bundle is not main_bundle and bundle.kind == ".appex"
    ]
    if not extensions or profile.bundle_identifier == WILDCARD_BUNDLE_ID:
        return
    names = ", ".join(
        f"{bundle.root.name} -> "
        + ipa_mod.child_bundle_id(
            original_bundle_id, signed_bundle_id, bundle.bundle_identifier
        )
        for bundle in extensions
    )
    raise errors.ProfileError(
        f"the profile provisions only {profile.bundle_identifier}; it "
        f"cannot cover the app extensions ({names})",
        hint="use a wildcard profile (application-identifier TEAMID.*), "
        "remove PlugIns from the IPA, or sign with an Apple ID so each "
        "extension gets its own profile",
    )


def sign_with_certificate(
    *,
    ipa_path: Path,
    p12_path: Path,
    profile_path: Path,
    output_path: Path,
    udid: str | None,
    bundle_id_override: str | None = None,
    team_override: str | None = None,
    strict_entitlements: bool = False,
    prompt_passphrase: PassphraseProvider | None = None,
    store: keychain_mod.KeychainStore | None = None,
    backend: signer_mod.Signer | None = None,
) -> CertificateSignOutcome:
    """Sign one IPA with an existing certificate and provisioning
    profile. No Apple ID, no developer API call, no anisette, and no
    Keychain session is used anywhere in this path.

    Args:
        ipa_path: the unsigned input .ipa.
        p12_path: the .p12 holding the signing certificate and key.
        profile_path: the .mobileprovision to validate and embed.
        output_path: where the signed .ipa is written.
        udid: the target device when installing; None for sign only,
            which skips the profile device check.
        bundle_id_override: --bundle-id; must agree with the profile.
        team_override: --team; must agree with the profile team.
        strict_entitlements: fail instead of dropping entitlements the
            profile does not grant.
        prompt_passphrase: produces the p12 passphrase; defaults to
            read_p12_passphrase (getpass).
        store: KeychainStore used to import the identity; defaults to
            the real login Keychain store.
        backend: signing backend; defaults to the codesign KeychainSigner.

    Returns:
        the output path, the original and signed bundle ids, the parsed
        profile, and the signing identity.

    Raises:
        UsageError (exit 2) for missing files and conflicting flags;
        SigningError for a wrong passphrase; ProfileError and friends
        for an unusable profile; the ipa module's errors for a bad IPA.
    """
    ipa_path = Path(ipa_path).expanduser()
    p12_path = Path(p12_path).expanduser()
    profile_path = Path(profile_path).expanduser()

    # Usage failures first: nothing may prompt or mutate before every
    # input file is present.
    for label, path, hint in (
        ("IPA", ipa_path, "check the input path"),
        ("p12", p12_path, "check the --p12 path"),
        ("profile", profile_path, "check the --profile path"),
    ):
        if not path.is_file():
            raise errors.UsageError(f"{label} file not found: {path}", hint=hint)

    # The profile decides team, bundle id, devices, and expiry; parse
    # it before prompting so a broken profile never asks for a secret.
    try:
        profile_bytes = profile_path.read_bytes()
    except OSError as exc:
        raise errors.ProfileError(
            f"could not read the provisioning profile: {exc}"
        ) from exc
    profile = profile_mod.parse_mobileprovision(profile_bytes)

    if team_override is not None and team_override != profile.team_identifier:
        raise errors.UsageError(
            f"--team {team_override} does not match the profile team "
            f"{profile.team_identifier}",
            hint="the team comes from the profile; drop --team or pass a "
            "profile issued by that team",
        )

    ipa_bundle = ipa_mod.extract_ipa(ipa_path)
    original_bundle_id = ipa_bundle.main_bundle.bundle_identifier
    signed_bundle_id, validation_bundle_id = _resolve_bundle_id(
        profile, bundle_id_override, original_bundle_id
    )

    # Full profile validation before any side effect: expiry, the
    # targeted device, the bundle id, and that a certificate is listed.
    # udid=None (sign only) skips the device check.
    profile_mod.assert_profile_usable(profile, udid, validation_bundle_id)
    bundles = _bundle_list(ipa_bundle)
    _check_extensions(
        profile, bundles, ipa_bundle.main_bundle, original_bundle_id, signed_bundle_id
    )

    # The passphrase is the last secret read; everything above is input
    # validation, everything below needs the key.
    prompt = read_p12_passphrase if prompt_passphrase is None else prompt_passphrase
    passphrase = prompt(p12_path)
    try:
        try:
            p12_bytes = p12_path.read_bytes()
        except OSError as exc:
            raise errors.SigningError(
                f"could not read {p12_path.name}: {exc}"
            ) from exc
        # Fail on a wrong passphrase or a cert-free p12 before the
        # import, then make sure the profile actually allows this
        # certificate to sign the app.
        identity_material = _unlock_p12(p12_bytes, passphrase, p12_path)
        certificate_der = identity_material.certificate.public_bytes(
            serialization.Encoding.DER
        )
        if certificate_der not in profile.developer_certificates:
            raise errors.ProfileError(
                f"the certificate in {p12_path.name} is not included in "
                f"profile {profile.uuid}",
                hint="sign with the .p12 whose certificate the profile "
                "lists, or re-download a profile issued for this certificate",
            )
        keychain = store if store is not None else keychain_mod.KeychainStore()
        identity_name = _import_identity(
            keychain, p12_path, passphrase, profile.team_identifier, identity_material
        )
    finally:
        del passphrase
    identity = SigningIdentity(
        team_identifier=profile.team_identifier, keychain_identity=identity_name
    )

    print(f"team: {profile.team_identifier} (from the profile)")
    print(f"certificate: imported ({identity_name})")
    print(f"bundle id: {original_bundle_id} -> {signed_bundle_id}")

    # Info.plist and embedded.mobileprovision must be in place before
    # codesign seals CodeResources.
    for app_bundle in bundles:
        app_bundle.remove_appstore_artifacts()
    ipa_bundle.main_bundle.set_bundle_identifier(signed_bundle_id)
    ipa_bundle.main_bundle.embed_profile(profile.data)
    for app_bundle in bundles:
        if app_bundle is ipa_bundle.main_bundle or app_bundle.kind != ".appex":
            continue
        child_id = ipa_mod.child_bundle_id(
            original_bundle_id, signed_bundle_id, app_bundle.bundle_identifier
        )
        app_bundle.set_bundle_identifier(child_id)
        app_bundle.embed_profile(profile.data)
        print(f"extension: {child_id}")

    print(f"profile expires: {_format_datetime(profile.expiration_date)}")

    # Entitlements come from the profile; keys the app requests beyond
    # it are dropped with a warning (or an error in strict mode).
    strict = strict_entitlements
    entitlements_by_path: dict[str, dict[str, object]] = {}
    root = ipa_bundle.main_bundle.root
    for app_bundle in bundles:
        original_entitlements = entitlements_mod.read_entitlements(
            app_bundle.executable
        )
        merged, dropped = entitlements_mod.build_entitlements(
            profile, original_entitlements, None, strict
        )
        for key in dropped:
            print(
                f"warning: entitlement '{key}' is not granted by the "
                "profile and was dropped"
            )
            if key.startswith("com.apple.private."):
                print(
                    "  apps that need private entitlements install but are "
                    "killed at launch by amfid on a stock device"
                )
        for macho in app_bundle.signable_inventory():
            entitlements_by_path[str(macho.relative_to(root))] = merged

    signer = backend if backend is not None else signer_mod.KeychainSigner()
    signer.sign_bundle(ipa_bundle.main_bundle, entitlements_by_path, identity)
    problems = signer.verify_bundle(ipa_bundle.main_bundle)
    if problems:
        raise errors.SigningError(
            "the signed bundle failed verification: " + "; ".join(problems)
        )

    output = Path(output_path).expanduser()
    output.parent.mkdir(parents=True, exist_ok=True)
    ipa_mod.repack_ipa(ipa_bundle, output)
    print(f"output: {output}")

    return CertificateSignOutcome(
        output_ipa=str(output),
        original_bundle_id=original_bundle_id,
        signed_bundle_id=signed_bundle_id,
        profile=profile,
        identity=identity,
    )
