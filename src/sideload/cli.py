"""Command line interface: argument parsing and dispatch only.

This module owns no business logic. Each command handler is a short
adapter that wires the owning modules together and converts their
exceptions into exit codes and user output. The full command contract,
including flags and observable behavior, is pinned in ACCEPTANCE.md.

Ownership: shared (GLUE agent). Command ownership:
    auth login/logout/status   calls apple.auth + keychain (AUTH modules)
    devices                    calls device.usbmux (DEVICE)
    apps                       calls device.installer (DEVICE)
    sign                       calls apple.developer + signing.* (SIGN);
                               with --p12 + --profile it runs the
                               certificate pipeline (signing.certificate)
    install                    calls sign pipeline + device.installer
    uninstall                  calls device.installer (DEVICE)
    refresh                    calls daemon helpers + the sign pipeline
    daemon                     calls daemon.RefreshDaemon (GLUE)
    doctor                     calls device.* + config (DEVICE + GLUE)
"""

from __future__ import annotations

import argparse
import getpass
import os
import re
import secrets
import sys
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path

from sideload import __version__, errors
from sideload import cache as cache_mod
from sideload import config as config_mod
from sideload import daemon as daemon_mod
from sideload import keychain as keychain_mod
from sideload.apple import anisette as anisette_mod
from sideload.apple import auth as auth_mod
from sideload.apple import developer as developer_mod
from sideload.device import installer as installer_mod
from sideload.device import usbmux as usbmux_mod
from sideload.models import (
    AppIDRecord,
    AppleSession,
    InstallRecord,
    ProvisioningProfile,
    SigningIdentity,
    Team,
)
from sideload.signing import certificate as certificate_mod
from sideload.signing import csr as csr_mod
from sideload.signing import customize as customize_mod
from sideload.signing import entitlements as entitlements_mod
from sideload.signing import injection as injection_mod
from sideload.signing import ipa as ipa_mod
from sideload.signing import profile as profile_mod
from sideload.signing import signer as signer_mod

PROGRAM = "sideload"

# How long "devices --pair" waits for the user to tap Trust.
PAIR_TIMEOUT_SECONDS = 120.0

# Device row labels keyed by the tri-state pairing / developer mode flag.
_BOOL_LABELS: dict[bool, dict[object, str]] = {
    True: {True: "yes", False: "no"},
    False: {True: "on", False: "off"},
}

# installation_proxy error names that warrant the doctor --follow-logs
# suggestion (the underlying amfid or installd reason is in the syslog).
_SIGNATURE_FAILURE_NAMES = frozenset(
    {
        "ApplicationVerificationFailed",
        "BundleVerificationFailed",
        "EmbeddedProfileInstallFailed",
        "MismatchedApplicationIdentifierEntitlement",
    }
)


def _add_customization_flags(parser: argparse.ArgumentParser) -> None:
    """Sideloadly-style app customization flags shared by sign and install.

    All of them are optional; with none given the pipeline behaves
    exactly as before. The contracts live in signing/customize.py.
    """
    parser.add_argument(
        "--name",
        metavar="TEXT",
        help="set CFBundleDisplayName and CFBundleName",
    )
    parser.add_argument(
        "--remove-plugins",
        action="store_true",
        help="delete PlugIns/*.appex and watch content before any App ID "
        "or profile is created",
    )
    parser.add_argument(
        "--entitlements",
        metavar="PATH",
        help="merge entitlements from a plist; keys the profile does not "
        "grant are dropped with a warning (an error with --strict-entitlements)",
    )
    parser.add_argument(
        "--min-os",
        metavar="VERSION",
        help="set MinimumOSVersion (and DeploymentTarget when already present)",
    )
    parser.add_argument(
        "--supported-devices",
        metavar="LIST",
        nargs="+",
        help="replace UISupportedDevices; one device identifier per argument",
    )
    parser.add_argument(
        "--icon",
        metavar="PATH.png",
        help="replace the app icon PNGs using the macOS sips tool",
    )


def build_parser() -> argparse.ArgumentParser:
    """The complete argument parser. Flag surface is frozen here so
    ACCEPTANCE.md stays truthful.
    """
    parser = argparse.ArgumentParser(
        prog=PROGRAM,
        description="Sign and install iOS IPAs over USB with an Apple developer identity.",
        epilog=(
            "commands: auth login, auth status, auth logout, devices, apps, "
            "sign, install, uninstall, refresh, daemon, doctor"
        ),
    )
    parser.add_argument("--version", action="version", version=__version__)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--udid",
        metavar="UDID",
        help="target device UDID; when omitted, the sole connected USB device is used",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    auth = subparsers.add_parser("auth", help="Apple ID login and session management")
    auth_sub = auth.add_subparsers(dest="auth_command", required=True)
    auth_login = auth_sub.add_parser("login", help="log in and store a session in the Keychain")
    auth_login.add_argument("--email", help="Apple ID email (prompted when omitted)")
    auth_login.add_argument(
        "--rotate-certificate",
        action="store_true",
        help="revoke the previous development certificate before requesting a new one",
    )
    auth_sub.add_parser("status", help="show stored session, team, and tool checks")
    auth_sub.add_parser("logout", help="delete the stored session from the Keychain")

    devices = subparsers.add_parser(
        "devices", parents=[common], help="list connected USB devices"
    )
    devices.add_argument(
        "--pair",
        action="store_true",
        help="pair the device before listing, prompting the Trust dialog",
    )

    apps = subparsers.add_parser(
        "apps", parents=[common], help="list apps installed on a device"
    )
    apps.add_argument("--all", action="store_true", help="include system apps")

    sign = subparsers.add_parser("sign", help="sign an IPA without installing")
    sign.add_argument("ipa", metavar="IPA", help="input .ipa path")
    sign.add_argument("--output", metavar="OUT", help="output .ipa path")
    sign.add_argument(
        "--bundle-id", metavar="ID", help="override the resigned bundle identifier"
    )
    sign.add_argument(
        "--team", metavar="TEAMID", help="use this team when the account has several"
    )
    sign.add_argument(
        "--strict-entitlements",
        action="store_true",
        help="fail instead of dropping entitlements the profile does not grant",
    )
    _add_customization_flags(sign)
    sign.add_argument(
        "--inject",
        metavar="DYLIB",
        action="append",
        help=(
            "inject a .dylib into the app's Frameworks directory and load it at "
            "launch; repeatable"
        ),
    )
    sign.add_argument(
        "--inject-deb",
        metavar="DEB",
        action="append",
        help=(
            "inject every MobileSubstrate dylib from a .deb tweak package; "
            "nothing is installed on the device; repeatable"
        ),
    )
    sign.add_argument(
        "--p12",
        metavar="PATH",
        help="sign with an existing developer certificate (.p12) instead of an Apple ID session",
    )
    sign.add_argument(
        "--profile",
        metavar="PATH",
        help="the .mobileprovision to sign with (required together with --p12)",
    )

    install_parser = subparsers.add_parser(
        "install", parents=[common], help="sign an IPA and install it over USB"
    )
    install_parser.add_argument("ipa", metavar="IPA", help="input .ipa path")
    install_parser.add_argument(
        "--bundle-id", metavar="ID", help="override the resigned bundle identifier"
    )
    install_parser.add_argument(
        "--team", metavar="TEAMID", help="use this team when the account has several"
    )
    install_parser.add_argument(
        "--strict-entitlements",
        action="store_true",
        help="fail instead of dropping entitlements the profile does not grant",
    )
    _add_customization_flags(install_parser)
    install_parser.add_argument(
        "--inject",
        metavar="DYLIB",
        action="append",
        help=(
            "inject a .dylib into the app's Frameworks directory and load it at "
            "launch; repeatable"
        ),
    )
    install_parser.add_argument(
        "--inject-deb",
        metavar="DEB",
        action="append",
        help=(
            "inject every MobileSubstrate dylib from a .deb tweak package; "
            "nothing is installed on the device; repeatable"
        ),
    )
    install_parser.add_argument(
        "--p12",
        metavar="PATH",
        help="sign with an existing developer certificate (.p12) instead of an Apple ID session",
    )
    install_parser.add_argument(
        "--profile",
        metavar="PATH",
        help="the .mobileprovision to sign with (required together with --p12)",
    )

    uninstall = subparsers.add_parser(
        "uninstall", parents=[common], help="uninstall an app from a device"
    )
    uninstall.add_argument("bundle_id", metavar="BUNDLE_ID", help="app bundle identifier")
    uninstall.add_argument(
        "--yes",
        action="store_true",
        help="required confirmation that data loss is accepted",
    )

    doctor = subparsers.add_parser(
        "doctor", parents=[common], help="diagnose tool, pairing, and developer mode state"
    )
    doctor.add_argument(
        "--follow-logs",
        action="store_true",
        help="stream filtered device syslog lines to find signature failures",
    )

    refresh = subparsers.add_parser(
        "refresh",
        parents=[common],
        help="re-sign and reinstall recorded apps before their profiles expire",
    )
    refresh.add_argument(
        "--all",
        action="store_true",
        help="refresh every device that has install records",
    )

    daemon = subparsers.add_parser(
        "daemon", help="manage the daily auto refresh launchd agent"
    )
    daemon_sub = daemon.add_subparsers(dest="daemon_command", required=True)
    daemon_sub.add_parser(
        "install", help="write and load the refresh LaunchAgent plist"
    )
    daemon_sub.add_parser(
        "uninstall", help="unload and remove the refresh LaunchAgent plist"
    )
    daemon_sub.add_parser(
        "status", help="show whether the refresh agent is installed and loaded"
    )

    return parser


# ---------------------------------------------------------------- helpers


def _normalize_dt(value: datetime) -> datetime:
    """Assume UTC for naive datetimes."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


def _format_datetime(value: datetime) -> str:
    return _normalize_dt(value).strftime("%Y-%m-%d %H:%M:%S %Z")


def _prompt(label: str) -> str:
    """Read one line from the user; EOF turns into a usage error."""
    try:
        return input(label).strip()
    except EOFError:
        raise errors.UsageError(f"could not read input; {label.strip()} is required") from None


def _ensure_state() -> tuple[config_mod.AppPaths, config_mod.SideloadConfig]:
    paths = config_mod.get_paths()
    config_mod.ensure_dirs(paths)
    return paths, config_mod.load_config(paths)


def _load_session() -> tuple[
    config_mod.AppPaths,
    config_mod.SideloadConfig,
    keychain_mod.KeychainStore,
    AppleSession,
]:
    """Session per DESIGN data flow step 1: load it, else exit 3 with a
    notice to run "sideload auth login".
    """
    paths, settings = _ensure_state()
    if not settings.email:
        raise errors.SessionExpiredError(
            "no Apple ID session is stored",
            hint="run: sideload auth login",
        )
    store = keychain_mod.KeychainStore()
    session = store.load_session(settings.email)
    if session is None:
        raise errors.SessionExpiredError(
            f"no session found in the Keychain for {settings.email}",
            hint="run: sideload auth login",
        )
    if _normalize_dt(session.token_expiry) <= datetime.now(UTC):
        raise errors.SessionExpiredError(
            f"the session for {settings.email} expired at {_format_datetime(session.token_expiry)}",
            hint="run: sideload auth login",
        )
    return paths, settings, store, session


def _select_team(teams: list[Team], requested: str | None, cached: Team | None) -> Team:
    """Pick the team: --team, else the cached selection, else the only
    team, else the single free personal team (DESIGN data flow step 3).
    """
    if requested:
        for team in teams:
            if team.identifier == requested:
                return team
        available = ", ".join(team.identifier for team in teams)
        raise errors.UsageError(
            f"team {requested} is not available for this account (available: {available})"
        )
    if cached is not None:
        for team in teams:
            if team.identifier == cached.identifier:
                return team
    if len(teams) == 1:
        return teams[0]
    free = [team for team in teams if team.is_free]
    if len(free) == 1:
        return free[0]
    listing = "\n".join(
        f"  {team.identifier}  {team.name} ({'free' if team.is_free else 'paid'})"
        for team in teams
    )
    raise errors.UsageError(
        "the account has several teams; pass --team TEAMID:\n" + listing
    )


def _resolve_udid(args: argparse.Namespace, transport: usbmux_mod.LibimobiledeviceTransport) -> str:
    """Target device: --udid, else the sole connected USB device, else
    the remembered default device, else a usage error listing them.
    """
    requested = getattr(args, "udid", None)
    if requested:
        return str(requested)
    devices = transport.list_devices()
    if not devices:
        raise errors.NoDeviceFoundError(
            "no USB device is connected",
            hint="plug the iPhone in over USB, unlock it, and tap Trust if prompted",
        )
    if len(devices) == 1:
        _remember_default_device(devices[0].udid)
        return devices[0].udid
    paths = config_mod.get_paths()
    settings = config_mod.load_config(paths)
    if settings.default_device:
        wanted = usbmux_mod.normalize_udid(settings.default_device)
        for device in devices:
            if usbmux_mod.normalize_udid(device.udid) == wanted:
                return device.udid
    listing = "\n".join(f"  {device.udid}" for device in devices)
    raise errors.UsageError(f"several USB devices are connected:\n{listing}\npass --udid UDID")


def _remember_default_device(udid: str) -> None:
    """Persist the default device preference; never fatal."""
    try:
        paths = config_mod.get_paths()
        settings = config_mod.load_config(paths)
        if settings.default_device != udid:
            config_mod.save_config(paths, replace(settings, default_device=udid))
    except OSError:
        return


def _print_tool_table() -> None:
    """The found or missing tool check table for auth status and doctor."""
    print("tools:")
    optional = set(config_mod.OPTIONAL_TOOLS)
    for name, path in config_mod.check_tools().items():
        if path is not None:
            print(f"  {name}: found ({path})")
            continue
        hint = config_mod.TOOL_INSTALL_HINTS.get(name, "install it and retry")
        suffix = " (optional)" if name in optional else ""
        print(f"  {name}: missing{suffix}; run: {hint}")


def _app_id_name(bundle_id: str) -> str:
    """Alphanumeric App ID name (AltSign sanitizes the same way)."""
    cleaned = re.sub(r"[^A-Za-z0-9]", "", bundle_id)
    return cleaned[-30:] or "sideload"


def _package_p12(
    certificate_pem: bytes, private_key_pem: bytes, paths: config_mod.AppPaths
) -> tuple[Path, str]:
    """Wrap the issued certificate and the local private key into a .p12
    for keychain.import_identity. GLUE helper: no SIGN module owns p12
    packaging in the pinned interfaces, and the key must not touch the
    state directory, so the bytes go straight into a 0600 temp file.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
    from cryptography.hazmat.primitives.serialization import pkcs12

    certificate = x509.load_pem_x509_certificate(certificate_pem)
    key = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        raise errors.SigningError(
            "the generated private key is not usable for code signing"
        )
    password = secrets.token_urlsafe(18)
    # "security import" (SecKeychainItemImport) rejects the modern p12
    # wrapping (AES plus a SHA-256 MAC) with "MAC verification failed";
    # only the legacy wrapping imports (verified live), so the p12 that
    # bridges our own serialization to the Keychain uses it.
    encryption = (
        serialization.PrivateFormat.PKCS12.encryption_builder()
        .kdf_rounds(50000)
        .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
        .hmac_hash(hashes.SHA1())
        .build(password.encode("utf-8"))
    )
    data = pkcs12.serialize_key_and_certificates(
        name=b"sideload",
        key=key,
        cert=certificate,
        cas=None,
        encryption_algorithm=encryption,
    )
    config_mod.ensure_dirs(paths)
    for stale in paths.cache_dir.glob("identity-*.p12"):
        stale.unlink(missing_ok=True)
    fd, name = tempfile.mkstemp(prefix="sideload-identity-", suffix=".p12")
    os.close(fd)
    p12_path = Path(name)
    os.chmod(p12_path, 0o600)
    p12_path.write_bytes(data)
    return p12_path, password


def _default_output(ipa_path: Path) -> Path:
    """The original file name plus ".signed.ipa"."""
    return ipa_path.with_name(ipa_path.stem + ".signed.ipa")


def _make_code_provider() -> Callable[[], str | None]:
    """Prompts for the six digit 2FA code, three attempts in total across
    every rejection (the GSA client re-calls after each bad code); None
    aborts. The budget is shared, not restarted per call.
    """
    attempts = 0

    def provider() -> str | None:
        nonlocal attempts
        while attempts < 3:
            attempts += 1
            code = _prompt(f"2FA code (attempt {attempts} of 3): ")
            if not code:
                return None
            if re.fullmatch(r"[0-9]{6}", code):
                return code
            print("the security code must be six digits")
        return None

    return provider


# ------------------------------------------------------------------ auth


def cmd_auth_login(args: argparse.Namespace) -> int:
    """Run Grand Slam login, prompting for password and 2FA code."""
    email = args.email or _prompt("Apple ID: ")
    if not email:
        raise errors.UsageError("an Apple ID email is required")
    try:
        password = getpass.getpass(f"Apple ID password for {email}: ")
    except EOFError:
        raise errors.AuthError("could not read the password; a password is required") from None
    if not password:
        raise errors.AuthError("a password is required")

    anisette_provider = anisette_mod.AnisetteProvider()
    client = auth_mod.GrandSlamClient(anisette_provider)
    session = client.authenticate(email, password, _make_code_provider())
    del password  # the password lives in memory only, never on disk

    paths = config_mod.get_paths()
    config_mod.ensure_dirs(paths)
    store = keychain_mod.KeychainStore()
    store.save_session(email, session)

    settings = config_mod.load_config(paths)
    settings = replace(
        settings,
        email=email,
        rotate_certificate=bool(getattr(args, "rotate_certificate", False))
        or settings.rotate_certificate,
    )
    config_mod.save_config(paths, settings)

    print(f"account: {session.account.first_name} {session.account.last_name}".rstrip())
    print(f"dsid: {session.dsid}")
    developer = developer_mod.DeveloperServiceClient(session, anisette_provider)
    teams = developer.fetch_teams()
    for team in teams:
        kind = "free" if team.is_free else "paid"
        print(f"team: {team.name} ({kind}) id {team.identifier}")
    print(f"session expires: {_format_datetime(session.token_expiry)}")
    return 0


def cmd_auth_status(args: argparse.Namespace) -> int:
    """Print stored session, expiry, selected team, and tool checks."""
    paths, settings = _ensure_state()
    if not settings.email:
        raise errors.SessionExpiredError(
            "no Apple ID session is stored",
            hint="run: sideload auth login",
        )
    store = keychain_mod.KeychainStore()
    session = store.load_session(settings.email)
    if session is None:
        raise errors.SessionExpiredError(
            f"no session found in the Keychain for {settings.email}",
            hint="run: sideload auth login",
        )
    expired = _normalize_dt(session.token_expiry) <= datetime.now(UTC)
    note = " (expired)" if expired else ""
    print(f"email: {session.account.email or settings.email}")
    print(f"dsid: {session.dsid}")
    print(f"token expiry: {_format_datetime(session.token_expiry)}{note}")
    cache = cache_mod.ResourceCache(paths)
    team = cache.load_team(session.dsid)
    if team is not None:
        kind = "free" if team.is_free else "paid"
        print(f"selected team: {team.name} ({kind}) id {team.identifier}")
    elif settings.selected_team:
        print(f"selected team: {settings.selected_team}")
    else:
        print("selected team: none")
    _print_tool_table()
    return 0


def cmd_auth_logout(args: argparse.Namespace) -> int:
    """Delete the stored session; keeps cached developer resources."""
    paths, settings = _ensure_state()
    if not settings.email:
        print("no stored session")
        return 0
    store = keychain_mod.KeychainStore()
    store.delete_session(settings.email)
    config_mod.save_config(paths, replace(settings, email=None))
    print(
        f"deleted the Keychain session for {settings.email}; "
        "cached profiles and App ID mirrors are kept"
    )
    return 0


# ---------------------------------------------------------------- devices


def _print_device_row(device: object) -> None:
    """One device line: UDID, name, product type, iOS version, pairing,
    developer mode (on, off, or unknown).
    """
    udid = getattr(device, "udid", "(unknown)")
    name = getattr(device, "name", None) or "(unknown)"
    product = getattr(device, "product_type", None) or "(unknown)"
    version = getattr(device, "product_version", None) or "(unknown)"
    paired = getattr(device, "paired", None)
    pairing_text = _BOOL_LABELS[True].get(paired, "unknown")
    mode = getattr(device, "developer_mode_enabled", None)
    mode_text = _BOOL_LABELS[False].get(mode, "unknown")
    print(
        f"{udid}  {name}  {product}  iOS {version}  "
        f"paired: {pairing_text}  developer mode: {mode_text}"
    )


def cmd_devices(args: argparse.Namespace) -> int:
    """List USB devices with pairing and developer mode state."""
    transport = usbmux_mod.LibimobiledeviceTransport()
    devices = transport.list_devices()
    if args.udid:
        wanted = usbmux_mod.normalize_udid(args.udid)
        devices = [
            device
            for device in devices
            if usbmux_mod.normalize_udid(device.udid) == wanted
        ]
    if not devices:
        raise errors.NoDeviceFoundError(
            "no USB device is connected",
            hint="plug the iPhone in over USB, unlock it, and tap Trust if prompted",
        )
    if args.pair:
        for device in devices:
            print(f"tap Trust on the device {device.udid}; waiting for pairing...")
            if not transport.wait_for_pair(device.udid, PAIR_TIMEOUT_SECONDS):
                print(f"pairing did not complete for {device.udid}")
    rows = [transport.read_device(device.udid) for device in devices]
    for row in rows:
        _print_device_row(row)
    if len(rows) == 1 and not args.udid:
        _remember_default_device(rows[0].udid)
    return 0


def cmd_apps(args: argparse.Namespace) -> int:
    """List installed apps on the target device."""
    transport = usbmux_mod.LibimobiledeviceTransport()
    udid = _resolve_udid(args, transport)
    if not transport.is_paired(udid):
        raise errors.PairingError(
            f"the device {udid} is not paired with this Mac",
            hint="run: sideload devices --pair",
        )
    client = installer_mod.DeviceAppClient(transport)
    apps = client.list_apps(udid, user_apps_only=not args.all)
    if not apps:
        print("no installed system apps" if args.all else "no installed user apps")
    for app in apps:
        label = app.name or app.bundle_identifier
        version = f" ({app.version})" if app.version else ""
        print(f"{app.bundle_identifier} - {label}{version}")
    return 0


# ------------------------------------------------------------------- sign


@dataclass(frozen=True)
class _SignOutcome:
    """Everything the shared sign pipeline produced for one IPA."""

    output_ipa: str
    original_bundle_id: str
    resigned_bundle_id: str
    app_id: AppIDRecord
    profile: ProvisioningProfile
    identity: SigningIdentity
    session: AppleSession
    paths: config_mod.AppPaths
    cache: cache_mod.ResourceCache


def _profile_covers(
    profile: ProvisioningProfile,
    team: Team,
    udid: str | None,
    certificate_der: bytes | None = None,
) -> bool:
    """True when a cached profile still matches team, device, and key."""
    if profile.team_identifier != team.identifier:
        return False
    if certificate_der is not None and certificate_der not in profile.developer_certificates:
        return False
    if udid is None:
        return True
    wanted = usbmux_mod.normalize_udid(udid)
    return any(
        usbmux_mod.normalize_udid(device) == wanted for device in profile.device_ids
    )


def _ensure_app_id(
    developer: developer_mod.DeveloperServiceClient,
    team: Team,
    cache: cache_mod.ResourceCache,
    dsid: str,
    app_ids: list[AppIDRecord],
    bundle_id: str,
) -> AppIDRecord:
    """Reuse or create one App ID, keeping the local list current."""
    record = next(
        (item for item in app_ids if item.bundle_identifier == bundle_id), None
    )
    if record is not None:
        print(f"app id: reused ({bundle_id})")
        return record
    if team.is_free and len(app_ids) >= 5:
        print(
            "warning: free accounts can register 10 App IDs per seven days; "
            f"{len(app_ids)} are already registered"
        )
    try:
        record = developer.add_app_id(_app_id_name(bundle_id), bundle_id, team)
    except errors.AppIDQuotaExceededError:
        print(
            "free accounts can register 10 App IDs per seven days; deleting an "
            "App ID does not restore quota, so wait for the oldest to age out"
        )
        first_seen = cache.app_id_first_seen(dsid)
        for existing in app_ids:
            seen = first_seen.get(existing.identifier)
            when = f", first seen {_format_datetime(seen)}" if seen else ""
            print(f"  existing app id: {existing.bundle_identifier}{when}")
        raise
    print(f"app id: created ({bundle_id})")
    app_ids.append(record)
    cache.save_app_ids(dsid, app_ids)
    return record


def _profile_for_bundle(
    developer: developer_mod.DeveloperServiceClient,
    team: Team,
    cache: cache_mod.ResourceCache,
    dsid: str,
    app_id: AppIDRecord,
    bundle_id: str,
    udid: str | None,
    certificate_der: bytes | None = None,
) -> ProvisioningProfile:
    """Reuse a cached profile only when it still covers this team and device."""
    profile = cache.find_profile_for_bundle(dsid, bundle_id)
    if profile is not None and _profile_covers(profile, team, udid, certificate_der):
        print(f"profile: reused ({profile.uuid})")
        return profile
    if profile is not None:
        print(f"profile: cached copy for {bundle_id} no longer matches; refreshing")
    profile = developer.fetch_provisioning_profile(app_id, team)
    cache.save_profile(dsid, profile)
    print(f"profile: fetched ({profile.uuid})")
    if certificate_der is None:
        print(
            f"warning: the signing certificate could not be read; "
            f"the profile for {bundle_id} was not certificate-checked"
        )
    elif certificate_der not in profile.developer_certificates:
        raise errors.ProfileError(
            f"the profile for {bundle_id} does not include the current signing certificate",
            hint=(
                "the certificate may have been revoked by another machine; run "
                "sideload auth login --rotate-certificate to issue a new one"
            ),
        )
    profile_mod.assert_profile_usable(profile, udid, bundle_id)
    return profile


def _sign_pipeline(
    args: argparse.Namespace, *, udid: str | None, device_name: str | None
) -> _SignOutcome:
    """The DESIGN data flow steps 3 to 11, shared by sign and install.

    Prints the sign summary in the ACCEPTANCE order: selected team,
    certificate created or reused, device registration skipped or
    done, App ID created or reused, profile expiry, dropped
    entitlement keys, and (handled by the caller) the output path.
    """
    # App customization flags (signing/customize.py) are validated
    # first, so a bad --min-os or a missing file can never waste an
    # Apple request; the edits themselves are applied right after the
    # IPA is extracted, before the App ID / profile / entitlement loop
    # and long before signing seals CodeResources.
    customization = customize_mod.build_customization(
        name=getattr(args, "name", None),
        remove_plugins=bool(getattr(args, "remove_plugins", False)),
        entitlements_path=getattr(args, "entitlements", None),
        min_os=getattr(args, "min_os", None),
        supported_devices=getattr(args, "supported_devices", None),
        icon_path=getattr(args, "icon", None),
    )
    paths, settings, store, session = _load_session()
    cache = cache_mod.ResourceCache(paths)

    anisette_provider = anisette_mod.AnisetteProvider()
    developer = developer_mod.DeveloperServiceClient(session, anisette_provider)

    # step 3: pick the team
    teams = developer.fetch_teams()
    team = _select_team(teams, getattr(args, "team", None), cache.load_team(session.dsid))
    kind = "free" if team.is_free else "paid"
    print(f"team: {team.name} ({kind}) id {team.identifier}")
    cache.save_team(session.dsid, team)
    if settings.selected_team != team.identifier:
        config_mod.save_config(paths, replace(settings, selected_team=team.identifier))

    # Validate the input before any destructive Apple side effect.
    ipa_path = Path(args.ipa).expanduser()
    if not ipa_path.is_file():
        raise errors.UsageError(f"IPA file not found: {ipa_path}")
    bundle = ipa_mod.extract_ipa(ipa_path)

    # Plugin removal runs here on purpose: before the App ID, profile,
    # and entitlement loop below, with the bundle inventory recomputed
    # so removed extensions are never provisioned or signed.
    for note in customize_mod.apply_customization(bundle, customization):
        print(note)
    # Tweak and dylib injection sits between extraction and signing:
    # the copied dylibs are loose Mach-O files inside Frameworks, so
    # signable_inventory picks them up and the signer signs them before
    # the app executable. Injection runs before any Apple API side
    # effect later in this function, so a bad input aborts cheaply.
    # Without the flags the call is skipped entirely, so the no flag
    # path is unchanged.
    inject_dylibs = [
        Path(str(item)).expanduser() for item in (getattr(args, "inject", None) or [])
    ]
    inject_debs = [
        Path(str(item)).expanduser() for item in (getattr(args, "inject_deb", None) or [])
    ]
    if inject_dylibs or inject_debs:
        injection_mod.apply_injections(bundle, inject_dylibs, inject_debs)

    # step 4: ensure the signing certificate exists
    machine_name = csr_mod.make_machine_name()
    identity_certificate_der: bytes | None = None
    identity = store.find_identity(team.identifier)
    if identity is not None and settings.rotate_certificate:
        # An explicit rotation must replace the identity even when one is
        # already present; otherwise a revoked certificate is reused on
        # every run and the flag never clears.
        print("certificate: rotating the local identity")
        if identity.keychain_identity is not None:
            store.delete_identity(identity.keychain_identity)
        identity = None
    if identity is not None:
        print("certificate: reused from the Keychain")
        if identity.keychain_identity is not None:
            identity_certificate_der = store.identity_certificate_der(
                identity.keychain_identity
            )
    else:
        if settings.rotate_certificate:
            # Revoke only certificates issued to this Mac. Other machines
            # in the same team must not lose their signing identity.
            for certificate in developer.list_certificates(team):
                if certificate.machine_name != machine_name:
                    continue
                developer.revoke_certificate(certificate, team)
                print(f"revoked previous certificate {certificate.identifier}")
            settings = replace(settings, rotate_certificate=False)
            config_mod.save_config(paths, settings)
        private_key_pem = csr_mod.generate_private_key()
        machine_id = csr_mod.load_or_create_machine_id(
            str(paths.cache_dir / "machine-id")
        )
        csr_pem = csr_mod.create_csr(private_key_pem, machine_name)
        certificate = developer.create_development_certificate(
            csr_pem, machine_name, team, machine_id=machine_id
        )
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding

        identity_certificate_der = x509.load_pem_x509_certificate(
            certificate.certificate_pem
        ).public_bytes(Encoding.DER)
        p12_path, p12_password = _package_p12(certificate.certificate_pem, private_key_pem, paths)
        try:
            identity_name = store.import_identity(
                str(p12_path), p12_password, team.identifier
            )
        finally:
            p12_path.unlink(missing_ok=True)
        identity = SigningIdentity(
            team_identifier=team.identifier, keychain_identity=identity_name
        )
        print("certificate: created and imported into the Keychain")

    # step 6 (bundle id) and step 8 (IPA inventory)
    original_bundle_id = bundle.main_bundle.bundle_identifier
    resigned_bundle_id = str(
        getattr(args, "bundle_id", None) or ""
    ) or ipa_mod.resign_bundle_id(original_bundle_id, team.identifier)
    print(f"bundle id: {original_bundle_id} -> {resigned_bundle_id}")

    # step 5: register the device with the team (install only)
    if udid is None:
        print("device registration: skipped (no device; sign only)")
    else:
        team_devices = developer.fetch_devices(team)
        cache.save_devices(session.dsid, team_devices)
        registered = any(
            usbmux_mod.normalize_udid(record.identifier) == usbmux_mod.normalize_udid(udid)
            for record in team_devices
        )
        if registered:
            print(f"device registration: reused ({udid})")
        else:
            try:
                developer.register_device(device_name or udid, udid, team)
            except errors.DeviceAlreadyRegisteredError:
                pass
            print(f"device registration: done ({udid})")

    # step 6: one App ID per bundle (main app plus each extension)
    app_ids = developer.fetch_app_ids(team)
    cache.save_app_ids(session.dsid, app_ids)
    # Apple treats bundle identifiers case-insensitively for uniqueness.
    # Sideloadly registered the uppercase team suffix, so the default
    # lowercase id would collide with it on addAppId. Reuse the existing
    # record and sign with its exact case.
    existing_case = next(
        (
            record
            for record in app_ids
            if record.bundle_identifier.casefold() == resigned_bundle_id.casefold()
        ),
        None,
    )
    if (
        existing_case is not None
        and existing_case.bundle_identifier != resigned_bundle_id
    ):
        print(
            "bundle id: reusing existing case "
            f"{existing_case.bundle_identifier}"
        )
        resigned_bundle_id = existing_case.bundle_identifier
    app_id = _ensure_app_id(
        developer, team, cache, session.dsid, app_ids, resigned_bundle_id
    )

    # step 7: one profile per bundle, cached only while it still matches
    bundles = list(getattr(bundle, "all_bundles", []) or [])
    if bundle.main_bundle not in bundles:
        bundles.insert(0, bundle.main_bundle)

    for app_bundle in bundles:
        app_bundle.remove_appstore_artifacts()

    main_profile = _profile_for_bundle(
        developer,
        team,
        cache,
        session.dsid,
        app_id,
        resigned_bundle_id,
        udid,
        identity_certificate_der,
    )
    profiles_by_root: dict[Path, ProvisioningProfile] = {
        bundle.main_bundle.root: main_profile
    }

    # The Info.plist identifier and the embedded profile must be in place
    # before codesign seals CodeResources.
    bundle.main_bundle.set_bundle_identifier(resigned_bundle_id)
    bundle.main_bundle.embed_profile(main_profile.data)

    for app_bundle in bundles:
        if app_bundle is bundle.main_bundle or app_bundle.kind != ".appex":
            continue
        child_id = ipa_mod.child_bundle_id(
            original_bundle_id, resigned_bundle_id, app_bundle.bundle_identifier
        )
        app_bundle.set_bundle_identifier(child_id)
        child_app_id = _ensure_app_id(
            developer, team, cache, session.dsid, app_ids, child_id
        )
        child_profile = _profile_for_bundle(
            developer,
            team,
            cache,
            session.dsid,
            child_app_id,
            child_id,
            udid,
            identity_certificate_der,
        )
        app_bundle.embed_profile(child_profile.data)
        profiles_by_root[app_bundle.root] = child_profile
        print(f"extension: {child_id}")

    print(f"profile expires: {_format_datetime(main_profile.expiration_date)}")

    # step 9: entitlements per bundle; --entitlements keys flow through
    # build_entitlements' extra parameter, pre-filtered against each
    # bundle's own profile so keys the profile does not grant still get
    # dropped with a warning (an error under --strict-entitlements).
    strict = bool(getattr(args, "strict_entitlements", False))
    custom_entitlements = customization.extra_entitlements
    entitlements_by_path: dict[str, dict[str, object]] = {}
    bundles = list(getattr(bundle, "all_bundles", []) or [])
    if bundle.main_bundle not in bundles:
        bundles.insert(0, bundle.main_bundle)
    root = bundle.main_bundle.root
    for app_bundle in bundles:
        bundle_profile = profiles_by_root.get(app_bundle.root, main_profile)
        original_entitlements = entitlements_mod.read_entitlements(app_bundle.executable)
        extra: dict[str, object] | None = None
        if custom_entitlements:
            extra, custom_dropped = customize_mod.split_extra_entitlements(
                bundle_profile, custom_entitlements
            )
            if custom_dropped:
                if strict:
                    raise errors.EntitlementsError(
                        "--entitlements requests keys the profile does not "
                        "grant: " + ", ".join(custom_dropped),
                        dropped=custom_dropped,
                        hint=(
                            "sign again without --strict-entitlements to drop "
                            "these keys with a warning, or remove them from "
                            "the entitlements plist"
                        ),
                    )
                for key in custom_dropped:
                    print(
                        f"warning: entitlement '{key}' from --entitlements "
                        "is not granted by the profile and was dropped"
                    )
        merged, dropped = entitlements_mod.build_entitlements(
            bundle_profile, original_entitlements, extra, strict
        )
        for key in dropped:
            print(f"warning: entitlement '{key}' is not granted by the profile and was dropped")
            if key.startswith("com.apple.private."):
                print(
                    "  apps that need private entitlements install but are "
                    "killed at launch by amfid on a stock device"
                )
        for macho in app_bundle.signable_inventory():
            entitlements_by_path[str(macho.relative_to(root))] = merged

    # steps 10 and 11: sign deepest first, then repack
    backend = signer_mod.KeychainSigner()
    backend.sign_bundle(bundle.main_bundle, entitlements_by_path, identity)
    problems = backend.verify_bundle(bundle.main_bundle)
    if problems:
        raise errors.SigningError(
            "the signed bundle failed verification: " + "; ".join(problems)
        )
    output = (
        Path(str(getattr(args, "output", None))).expanduser()
        if getattr(args, "output", None)
        else _default_output(ipa_path)
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    ipa_mod.repack_ipa(bundle, output)
    print(f"output: {output}")

    return _SignOutcome(
        output_ipa=str(output),
        original_bundle_id=original_bundle_id,
        resigned_bundle_id=resigned_bundle_id,
        app_id=app_id,
        profile=main_profile,
        identity=identity,
        session=session,
        paths=paths,
        cache=cache,
    )


def _certificate_signing_requested(args: argparse.Namespace) -> bool:
    """True when --p12 or --profile was passed; the pair is validated
    together in _run_certificate_sign."""
    return bool(getattr(args, "p12", None)) or bool(getattr(args, "profile", None))


def _run_certificate_sign(
    args: argparse.Namespace, *, udid: str | None
) -> certificate_mod.CertificateSignOutcome:
    """Sign with an existing developer certificate and provisioning
    profile (signing/certificate.py). No Apple ID login, no developer
    API call, no anisette, and no Keychain session happens anywhere in
    this path; the p12 passphrase is read with getpass.
    """
    p12_value = getattr(args, "p12", None)
    profile_value = getattr(args, "profile", None)
    if not p12_value or not profile_value:
        missing = "--profile" if p12_value else "--p12"
        raise errors.UsageError(
            "--p12 and --profile must be passed together",
            hint=f"pass {missing} as well, or drop both to sign with an Apple ID session",
        )
    ipa_path = Path(args.ipa).expanduser()
    output = (
        Path(str(getattr(args, "output", None))).expanduser()
        if getattr(args, "output", None)
        else _default_output(ipa_path)
    )
    return certificate_mod.sign_with_certificate(
        ipa_path=ipa_path,
        p12_path=Path(str(p12_value)).expanduser(),
        profile_path=Path(str(profile_value)).expanduser(),
        output_path=output,
        udid=udid,
        bundle_id_override=getattr(args, "bundle_id", None),
        team_override=getattr(args, "team", None),
        strict_entitlements=bool(getattr(args, "strict_entitlements", False)),
    )


def _prepare_install_device(
    args: argparse.Namespace,
) -> tuple[usbmux_mod.LibimobiledeviceTransport, str, str | None]:
    """Resolve the install target and assert pairing and Developer Mode.
    No Apple or Keychain access happens here, so the certificate path
    shares this step without any Apple ID side effect.
    """
    transport = usbmux_mod.LibimobiledeviceTransport()
    udid = _resolve_udid(args, transport)
    if not transport.is_paired(udid):
        raise errors.PairingError(
            f"device {udid} is not paired with this Mac",
            hint='run "sideload devices --pair" and accept the trust dialog on the iPhone',
        )
    developer_mode = transport.developer_mode_enabled(udid)
    if developer_mode is False:
        raise errors.DeveloperModeDisabledError(
            f"Developer Mode is off on device {udid}",
            hint=(
                "enable it on the device: Settings > Privacy and Security > "
                "Developer Mode, toggle it on, and restart the device"
            ),
        )
    device_name: str | None = None
    try:
        device_name = transport.read_device(udid).name
    except errors.SideloadError:
        device_name = None
    return transport, udid, device_name


def _install_signed_ipa(
    transport: usbmux_mod.LibimobiledeviceTransport,
    udid: str,
    output_ipa: str,
    bundle_id: str,
) -> None:
    """Drive installation_proxy with the pinned progress printing and
    the doctor hint on signature failures."""
    client = installer_mod.DeviceAppClient(transport)

    def _progress(stage: str, percent: int | None) -> None:
        suffix = f" ({percent}%)" if percent is not None else ""
        print(f"  {stage}{suffix}")

    try:
        client.install(udid, output_ipa, _progress, bundle_id=bundle_id)
    except errors.InstallError as exc:
        if exc.install_error_name in _SIGNATURE_FAILURE_NAMES:
            print("run: sideload doctor --follow-logs to see the underlying amfid or installd reason")
        raise


def _finish_install(
    udid: str,
    *,
    original_bundle_id: str,
    resigned_bundle_id: str,
    app_id_identifier: str,
    profile_uuid: str,
    dsid: str,
    ipa_path: str | None = None,
) -> None:
    """Record the install for doctor and refreshes, remember the
    default device, and print the closing line."""
    record = InstallRecord(
        original_bundle_id=original_bundle_id,
        resigned_bundle_id=resigned_bundle_id,
        app_id_identifier=app_id_identifier,
        profile_uuid=profile_uuid,
        dsid=dsid,
        udid=udid,
        installed_at=datetime.now(UTC),
        ipa_path=ipa_path,
    )
    paths, _settings = _ensure_state()
    cache_mod.ResourceCache(paths).record_install(record)
    _remember_default_device(udid)
    print(f"installed: {resigned_bundle_id}")


def cmd_sign(args: argparse.Namespace) -> int:
    """Full sign pipeline: login check, team, App ID, CSR, profile,
    entitlement merge, nested re-sign, repack. With --p12 and --profile
    the certificate pipeline runs instead: no Apple account is needed
    or contacted.
    """
    if _certificate_signing_requested(args):
        _run_certificate_sign(args, udid=None)
        return 0
    _sign_pipeline(args, udid=None, device_name=None)
    return 0


def cmd_install(args: argparse.Namespace) -> int:
    """Sign then install; the acceptance path of the whole tool. With
    --p12 and --profile the signing step is the certificate pipeline
    and no Apple ID session is required or used.
    """
    if _certificate_signing_requested(args):
        transport, udid, _device_name = _prepare_install_device(args)
        cert_outcome = _run_certificate_sign(args, udid=udid)
        _install_signed_ipa(
            transport, udid, cert_outcome.output_ipa, cert_outcome.signed_bundle_id
        )
        _finish_install(
            udid,
            original_bundle_id=cert_outcome.original_bundle_id,
            resigned_bundle_id=cert_outcome.signed_bundle_id,
            # No App ID exists in the certificate path; the profile
            # UUID is the closest analog for the install record.
            app_id_identifier=cert_outcome.profile.uuid,
            profile_uuid=cert_outcome.profile.uuid,
            dsid=cert_outcome.profile.team_identifier,
            ipa_path=str(Path(args.ipa).expanduser().resolve()),
        )
        return 0

    _load_session()  # exit 3 before touching the device or Apple
    transport, udid, device_name = _prepare_install_device(args)
    outcome = _sign_pipeline(args, udid=udid, device_name=device_name)
    profile_mod.assert_profile_usable(outcome.profile, udid, outcome.resigned_bundle_id)
    _install_signed_ipa(
        transport, udid, outcome.output_ipa, outcome.resigned_bundle_id
    )
    _finish_install(
        udid,
        original_bundle_id=outcome.original_bundle_id,
        resigned_bundle_id=outcome.resigned_bundle_id,
        app_id_identifier=outcome.app_id.identifier,
        profile_uuid=outcome.profile.uuid,
        dsid=outcome.session.dsid,
        ipa_path=str(Path(args.ipa).expanduser().resolve()),
    )
    return 0


# ---------------------------------------------------------------- refresh


def _refresh_targets(
    cache: cache_mod.ResourceCache,
    settings: config_mod.SideloadConfig,
    udid: str | None,
    all_devices: bool,
) -> list[tuple[str, list[InstallRecord]]]:
    """Which devices and records to refresh.

    --all targets every device with install records. Otherwise the
    target is --udid, else the remembered default device, else the sole
    device with records (a usage error when there are several).
    """
    if all_devices:
        return sorted(cache.load_all_install_records().items())
    if udid is None:
        udid = settings.default_device
    if udid is None:
        devices = sorted(cache.load_all_install_records())
        if not devices:
            return []
        if len(devices) > 1:
            listing = "\n".join(f"  {device}" for device in devices)
            raise errors.UsageError(
                "several devices have install records; pass --udid UDID or --all:\n"
                + listing
            )
        udid = devices[0]
    return [(udid, cache.load_install_records(udid))]


def _refresh_one_app(
    record: InstallRecord,
    udid: str,
    transport: usbmux_mod.LibimobiledeviceTransport,
    cache: cache_mod.ResourceCache,
    session_dsid: str,
    work_dir: Path,
) -> daemon_mod.RefreshAppOutcome:
    """Refresh one app: re-sign it from its recorded source IPA with the
    cached certificate, App ID, and profile (reused by the sign
    pipeline, which downloads a fresh profile only when needed), then
    reinstall it over USB. Never prompts; failures become one failed
    outcome instead of aborting the run.
    """

    def _outcome(
        status: daemon_mod.RefreshStatus, detail: str
    ) -> daemon_mod.RefreshAppOutcome:
        print(f"{status.value}: {record.resigned_bundle_id} - {detail}")
        return daemon_mod.RefreshAppOutcome(
            resigned_bundle_id=record.resigned_bundle_id,
            status=status,
            detail=detail,
        )

    if not record.ipa_path:
        return _outcome(
            daemon_mod.RefreshStatus.SKIPPED,
            "no source IPA is recorded; reinstall the app with: "
            "sideload install <ipa>",
        )
    if record.dsid != session_dsid:
        return _outcome(
            daemon_mod.RefreshStatus.SKIPPED,
            f"installed with another Apple ID (dsid {record.dsid}); "
            "log in with that account to refresh it",
        )
    ipa_path = daemon_mod.source_ipa_for(record)
    if ipa_path is None:
        # The record is kept; the file may come back.
        return _outcome(
            daemon_mod.RefreshStatus.SKIPPED,
            f"source IPA not found: {record.ipa_path}",
        )

    output = work_dir / f"{ipa_path.stem}.refresh.ipa"
    sign_args = argparse.Namespace(
        ipa=str(ipa_path),
        output=str(output),
        bundle_id=record.resigned_bundle_id,
        team=None,
        strict_entitlements=False,
        udid=udid,
    )
    try:
        device_name: str | None = None
        try:
            device_name = transport.read_device(udid).name
        except errors.SideloadError:
            device_name = None
        outcome = _sign_pipeline(sign_args, udid=udid, device_name=device_name)
        profile_mod.assert_profile_usable(outcome.profile, udid, outcome.resigned_bundle_id)
        client = installer_mod.DeviceAppClient(transport)

        def _progress(stage: str, percent: int | None) -> None:
            suffix = f" ({percent}%)" if percent is not None else ""
            print(f"  {stage}{suffix}")

        client.install(
            udid,
            outcome.output_ipa,
            _progress,
            bundle_id=outcome.resigned_bundle_id,
        )
    except errors.SessionExpiredError:
        # Stop the whole run: no Apple call beyond the first rejection.
        print(
            f"refresh stopped: Apple rejected the stored session while "
            f"refreshing {record.resigned_bundle_id}"
        )
        raise
    except errors.InstallError as exc:
        if exc.install_error_name in _SIGNATURE_FAILURE_NAMES:
            print("run: sideload doctor --follow-logs to see the underlying amfid or installd reason")
        return _outcome(daemon_mod.RefreshStatus.FAILED, exc.message)
    except errors.SideloadError as exc:
        return _outcome(daemon_mod.RefreshStatus.FAILED, exc.message)

    cache.record_install(
        replace(record, profile_uuid=outcome.profile.uuid, installed_at=datetime.now(UTC))
    )
    return _outcome(daemon_mod.RefreshStatus.REFRESHED, f"re-signed from {ipa_path}")


def cmd_refresh(args: argparse.Namespace) -> int:
    """Re-sign and reinstall recorded apps before the 7 day profile
    expires, unattended: no password, no 2FA, no trust prompts.

    A missing, expired, or Apple rejected session exits 3 before any
    further Apple call. Devices that are off or unpaired are skipped
    with a message; the run exits 1 only when an app failed or nothing
    could be refreshed, and 0 when every attempted app was refreshed.
    """
    if args.all and args.udid:
        raise errors.UsageError("--all and --udid are mutually exclusive")
    paths, settings, _store, session = _load_session()
    daemon_mod.assert_no_pending_rotation(settings)
    cache = cache_mod.ResourceCache(paths)
    transport = usbmux_mod.LibimobiledeviceTransport()
    targets = _refresh_targets(cache, settings, args.udid, bool(args.all))
    if not targets:
        print("no install records found; nothing to refresh")
        return errors.EXIT_ERROR

    connected = {
        usbmux_mod.normalize_udid(device.udid) for device in transport.list_devices()
    }
    outcomes: list[daemon_mod.RefreshAppOutcome] = []
    with tempfile.TemporaryDirectory(prefix="sideload-refresh-") as work_dir:
        for device_udid, records in targets:
            if not records:
                print(f"no install records for device {device_udid}; nothing to refresh")
                continue
            if usbmux_mod.normalize_udid(device_udid) not in connected:
                print(f"skipping device {device_udid}: it is not connected over USB")
                outcomes.extend(
                    daemon_mod.skip_outcomes(records, "device not connected")
                )
                continue
            try:
                paired = transport.is_paired(device_udid)
                developer_mode = transport.developer_mode_enabled(device_udid)
            except errors.DeviceError as exc:
                print(f"skipping device {device_udid}: {exc.message}")
                outcomes.extend(daemon_mod.skip_outcomes(records, exc.message))
                continue
            if not paired:
                print(f"skipping device {device_udid}: it is not paired with this Mac")
                outcomes.extend(
                    daemon_mod.skip_outcomes(records, "device not paired")
                )
                continue
            if developer_mode is False:
                print(f"skipping device {device_udid}: Developer Mode is off")
                print(
                    "  enable it on the device: Settings > Privacy and Security > "
                    "Developer Mode"
                )
                outcomes.extend(
                    daemon_mod.skip_outcomes(records, "Developer Mode is off")
                )
                continue
            for record in records:
                outcomes.append(
                    _refresh_one_app(
                        record,
                        device_udid,
                        transport,
                        cache,
                        session.dsid,
                        Path(work_dir),
                    )
                )
    print(daemon_mod.format_refresh_summary(outcomes), end="")
    return daemon_mod.refresh_exit_code(outcomes)


# ------------------------------------------------------------------ daemon


def cmd_daemon_install(args: argparse.Namespace) -> int:
    """Write and load the daily refresh LaunchAgent plist."""
    _ensure_state()  # the log directory must exist for launchd to write
    agent = daemon_mod.RefreshDaemon()
    plist_path = agent.install()
    print(f"launch agent: {plist_path}")
    print(f"command: {' '.join(daemon_mod.refresh_program_arguments())}")
    print(
        f"schedule: every {daemon_mod.START_INTERVAL_SECONDS} seconds "
        "(free profiles expire after 7 days)"
    )
    print(f"log: {agent.paths.log_path}")
    print("remove it with: sideload daemon uninstall")
    print(
        "note: the agent never prompts; it needs a valid Keychain session, "
        "so run 'sideload auth login' when the log shows exit 3"
    )
    return 0


def cmd_daemon_uninstall(args: argparse.Namespace) -> int:
    """Unload the refresh agent and remove its plist."""
    agent = daemon_mod.RefreshDaemon()
    if agent.uninstall():
        print(f"removed: {agent.paths.plist_path}")
    else:
        print(f"no launch agent plist at {agent.paths.plist_path}")
    print("the refresh agent is unloaded")
    return 0


def cmd_daemon_status(args: argparse.Namespace) -> int:
    """Report the plist file and the launchd state."""
    agent = daemon_mod.RefreshDaemon()
    status = agent.status()
    state = "present" if status.plist_exists else "missing"
    print(f"plist: {state} ({agent.paths.plist_path})")
    print("agent: loaded" if status.loaded else "agent: not loaded")
    print(f"log: {agent.paths.log_path}")
    return 0


# --------------------------------------------------------------- uninstall


def cmd_uninstall(args: argparse.Namespace) -> int:
    """Uninstall an app; requires --yes."""
    if not args.yes:
        raise errors.UsageError(
            "uninstall removes the app and its data; the --yes flag is required",
            hint="re-run: sideload uninstall <bundle-id> --yes",
        )
    transport = usbmux_mod.LibimobiledeviceTransport()
    udid = _resolve_udid(args, transport)
    client = installer_mod.DeviceAppClient(transport)
    client.uninstall(udid, args.bundle_id, confirmed=True)
    paths, _settings = _ensure_state()
    cache = cache_mod.ResourceCache(paths)
    cache.forget_install(udid, args.bundle_id)
    print(f"removed: {args.bundle_id}")
    return 0


# ------------------------------------------------------------------ doctor


def cmd_doctor(args: argparse.Namespace) -> int:
    """Health report: tools, pairing, developer mode, disk space."""
    paths, _settings = _ensure_state()
    _print_tool_table()
    transport = usbmux_mod.LibimobiledeviceTransport()
    udid: str | None = args.udid
    if udid is None:
        try:
            devices = transport.list_devices()
        except errors.SideloadError as exc:
            print(f"device discovery failed: {exc.message}")
            devices = []
        if len(devices) == 1:
            udid = devices[0].udid
        elif len(devices) > 1:
            print(f"{len(devices)} USB devices are connected; pass --udid to check one of:")
            for device in devices:
                print(f"  {device.udid}")
    if udid is None:
        if args.follow_logs:
            raise errors.NoDeviceFoundError(
                "no USB device connected; --follow-logs needs one",
                hint="plug the iPhone in over USB and unlock it",
            )
        print("no USB device connected; skipping the device checks")
        return 0

    client = installer_mod.DeviceAppClient(transport)
    for line in client.diagnose(udid, follow_logs=False):
        print(line)

    cache = cache_mod.ResourceCache(paths)
    records = cache.load_install_records(udid)
    print(f"apps installed by sideload: {len(records)}")
    for record in records:
        installed = _format_datetime(record.installed_at)
        print(f"  {record.resigned_bundle_id} (profile {record.profile_uuid}, installed {installed})")

    if args.follow_logs:
        client.follow_logs(udid)
    return 0


# ------------------------------------------------------------------- main

_AUTH_HANDLERS: dict[str, Callable[[argparse.Namespace], int]] = {
    "login": cmd_auth_login,
    "status": cmd_auth_status,
    "logout": cmd_auth_logout,
}

_DAEMON_HANDLERS: dict[str, Callable[[argparse.Namespace], int]] = {
    "install": cmd_daemon_install,
    "uninstall": cmd_daemon_uninstall,
    "status": cmd_daemon_status,
}

_COMMAND_HANDLERS: dict[str, Callable[[argparse.Namespace], int]] = {
    "devices": cmd_devices,
    "apps": cmd_apps,
    "sign": cmd_sign,
    "install": cmd_install,
    "refresh": cmd_refresh,
    "uninstall": cmd_uninstall,
    "doctor": cmd_doctor,
}


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point. Parses arguments, dispatches, and maps exceptions:
    UsageError to exit 2, SessionExpiredError to exit 3 with a re-login
    notice, any other SideloadError to exit 1 with its hint.
    """
    from sideload import trust

    trust.configure_system_trust()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "auth":
            handler = _AUTH_HANDLERS[args.auth_command]
        elif args.command == "daemon":
            handler = _DAEMON_HANDLERS[args.daemon_command]
        else:
            handler = _COMMAND_HANDLERS[args.command]
        return handler(args)
    except errors.SessionExpiredError as exc:
        print(f"error: {exc.message}", file=sys.stderr)
        print("run: sideload auth login", file=sys.stderr)
        return exc.exit_code
    except errors.SideloadError as exc:
        print(f"error: {exc.message}", file=sys.stderr)
        if exc.hint:
            print(f"hint: {exc.hint}", file=sys.stderr)
        return exc.exit_code
    except NotImplementedError as exc:
        print(
            f"error: component not implemented yet: {exc}",
            file=sys.stderr,
        )
        return errors.EXIT_ERROR
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return errors.EXIT_ERROR
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return errors.EXIT_ERROR
    finally:
        ipa_mod.cleanup_work_dirs()
