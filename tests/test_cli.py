"""Tests for the CLI slice: parser surface, exit codes, config and cache
persistence, and the full mocked sign/install flows.

Every device interaction is faked at the subprocess boundary and every
AUTH/SIGN collaborator is replaced with an in memory fake, so no test
contacts a device, Apple, or the Keychain.
"""

from __future__ import annotations

import getpass
import io
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from sideload import cache as cache_mod
from sideload import config, errors
from sideload import keychain as keychain_mod
from sideload.apple import anisette as anisette_mod
from sideload.apple import auth as auth_mod
from sideload.apple import developer as developer_mod
from sideload.cli import build_parser, main
from sideload.device import installer as installer_mod
from sideload.device import usbmux as usbmux_mod
from sideload.models import (
    Account,
    AppIDRecord,
    AppleSession,
    DeviceRecord,
    InstallRecord,
    ProvisioningProfile,
    SigningIdentity,
    Team,
    TeamType,
)
from sideload.signing import csr as csr_mod
from sideload.signing import entitlements as entitlements_mod
from sideload.signing import ipa as ipa_mod

# Captured before fixtures replace them, for the real-IPA integration test.
REAL_EXTRACT_IPA = ipa_mod.extract_ipa
REAL_REPACK_IPA = ipa_mod.repack_ipa
from sideload.signing import profile as profile_mod
from sideload.signing import signer as signer_mod

UDID = "00008101-000000000000000E"
EMAIL = "user@example.com"
DSID = "123456"
TEAM_ID = "TEAMID1"
RESIGNED_ID = "com.example.nightly.teamid1"


# ------------------------------------------------------------- fakes


class FakeResult:
    """Minimal stand in for subprocess.CompletedProcess[str]."""

    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class FakeRunner:
    """Routes tool invocations to scripted outputs keyed by tool name."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.by_tool: dict[str, object] = {}

    def script(self, tool: str, result: object) -> None:
        self.by_tool[tool] = result

    def __call__(self, cmd: Sequence[str], timeout: float | None = None) -> FakeResult:
        self.calls.append(list(cmd))
        name = Path(cmd[0]).name
        entry = self.by_tool.get(name)
        if entry is None:
            return FakeResult(returncode=0, stdout="", stderr="")
        if callable(entry):
            return entry(list(cmd))
        assert isinstance(entry, FakeResult)
        return entry


class FakePopen:
    """Minimal Popen stand in streaming canned lines."""

    def __init__(self, lines: Sequence[str]) -> None:
        self.stdout = io.StringIO("".join(lines))
        self.returncode = 0

    def terminate(self) -> None:
        return None

    def wait(self, timeout: float | None = None) -> int:
        return 0

    def kill(self) -> None:
        return None


class FakeKeychainStore:
    """In memory KeychainStore double recording session operations."""

    saved: list[tuple[str, AppleSession]] = []  # noqa: RUF012 - shared fake state
    deleted: list[str] = []  # noqa: RUF012 - shared fake state

    def __init__(self) -> None:
        return None

    @classmethod
    def reset(cls) -> None:
        cls.saved = []
        cls.deleted = []

    def load_session(self, email: str) -> AppleSession | None:
        return make_session(email)

    def save_session(self, email: str, session: AppleSession) -> None:
        FakeKeychainStore.saved.append((email, session))

    def delete_session(self, email: str) -> bool:
        FakeKeychainStore.deleted.append(email)
        return True

    def find_identity(self, team_identifier: str) -> SigningIdentity | None:
        return SigningIdentity(
            team_identifier=team_identifier,
            keychain_identity=f"Apple Development: {EMAIL} ({team_identifier})",
        )

    def identity_certificate_der(self, identity_name: str) -> bytes | None:
        return b"\x30\x82\x01\x00\x00\x00"

    def import_identity(self, p12_path: str, p12_password: str, identity_note: str) -> str:
        return f"Apple Development: {EMAIL} ({TEAM_ID})"

    def delete_identity(self, identity_name: str) -> None:
        return None


class FakeAnisette:
    """AnisetteProvider double; the CLI never reads headers itself."""

    def get_anisette(self) -> None:
        return None


class FakeGrandSlam:
    """GrandSlamClient double that accepts any credentials."""

    logins: list[tuple[str, str]] = []  # noqa: RUF012 - shared fake state

    def __init__(self, anisette: object) -> None:
        self.anisette = anisette

    @classmethod
    def reset(cls) -> None:
        cls.logins = []

    def authenticate(
        self, email: str, password: str, security_code_provider: Callable[[], str | None]
    ) -> AppleSession:
        FakeGrandSlam.logins.append((email, password))
        return make_session(email)


class RejectingTwoFactorGrandSlam(FakeGrandSlam):
    """Never accepts a 2FA code; exercised until the provider gives up."""

    def authenticate(
        self, email: str, password: str, security_code_provider: Callable[[], str | None]
    ) -> AppleSession:
        while True:
            code = security_code_provider()
            if code is None:
                raise errors.TwoFactorError("the security code was rejected")


class FakeDeveloperService:
    """DeveloperServiceClient double speaking the pinned interface."""

    registered: list[DeviceRecord] = []  # noqa: RUF012 - shared fake state
    created_app_ids: list[str] = []  # noqa: RUF012 - shared fake state

    def __init__(self, session: AppleSession, anisette: object) -> None:
        self.session = session
        self.anisette = anisette

    @classmethod
    def reset(cls) -> None:
        cls.registered = []
        cls.created_app_ids = []

    def fetch_teams(self) -> list[Team]:
        return [Team(identifier=TEAM_ID, name="Personal Team", team_type=TeamType.FREE)]

    def fetch_devices(self, team: Team) -> list[DeviceRecord]:
        return list(FakeDeveloperService.registered)

    def register_device(self, name: str, udid: str, team: Team) -> DeviceRecord:
        record = DeviceRecord(name=name, identifier=udid)
        FakeDeveloperService.registered.append(record)
        return record

    def list_certificates(self, team: Team) -> list[object]:
        return []

    def create_development_certificate(
        self, csr_pem: str, machine_name: str, team: Team
    ) -> object:
        raise AssertionError("the fake identity is reused; no CSR should be submitted")

    def revoke_certificate(self, certificate: object, team: Team) -> None:
        return None

    def fetch_app_ids(self, team: Team) -> list[AppIDRecord]:
        return []

    def add_app_id(self, name: str, bundle_identifier: str, team: Team) -> AppIDRecord:
        FakeDeveloperService.created_app_ids.append(bundle_identifier)
        return AppIDRecord(
            identifier="APPID1", name=name, bundle_identifier=bundle_identifier
        )

    def fetch_provisioning_profile(self, app_id: AppIDRecord, team: Team) -> ProvisioningProfile:
        return make_profile("PROFILE-UUID-1", app_id.bundle_identifier, days=7.0)


class FakeSigner:
    """KeychainSigner double recording sign calls; verification passes."""

    signed: list[tuple[object, object, object]] = []  # noqa: RUF012 - shared fake state

    def __init__(self) -> None:
        return None

    @classmethod
    def reset(cls) -> None:
        cls.signed = []

    def sign_bundle(
        self,
        bundle: object,
        entitlements_by_path: dict[str, dict[str, object]],
        identity: SigningIdentity,
    ) -> None:
        FakeSigner.signed.append((bundle, entitlements_by_path, identity))

    def verify_bundle(self, bundle: object) -> list[str]:
        return []


class FakeAppBundle:
    """AppBundle double with the fields the CLI pipeline touches."""

    def __init__(self, root: Path, bundle_identifier: str) -> None:
        self.root = root
        self.bundle_identifier = bundle_identifier
        self.executable = root / "Nightly"
        self.info_plist_path = root / "Info.plist"
        self.embedded_profile: bytes | None = None

    @property
    def kind(self) -> str:
        return self.root.suffix

    def remove_appstore_artifacts(self) -> None:
        self.artifacts_removed = True

    def set_bundle_identifier(self, new_bundle_id: str) -> None:
        self.bundle_identifier = new_bundle_id

    def embed_profile(self, profile_data: bytes) -> None:
        self.embedded_profile = profile_data

    def signable_inventory(self) -> list[Path]:
        return [self.executable]


class FakeIPABundle:
    """IPABundle double wrapping one fake app bundle."""

    def __init__(self, main_bundle: FakeAppBundle) -> None:
        self.ipa_path = main_bundle.root
        self.work_dir = main_bundle.root.parent
        self.main_bundle = main_bundle
        self.all_bundles = [main_bundle]


def make_session(email: str = EMAIL) -> AppleSession:
    expiry = datetime.now(UTC) + timedelta(days=30.0)
    account = Account(first_name="Test", last_name="User", email=email, dsid=DSID)
    return AppleSession(
        dsid=DSID, gs_token="gs-token-value", token_expiry=expiry, account=account
    )


def make_profile(uuid: str, bundle_id: str, days: float) -> ProvisioningProfile:
    now = datetime.now(UTC)
    return ProvisioningProfile(
        identifier="PP1",
        uuid=uuid,
        name="iOS Team Provisioning Profile",
        team_identifier=TEAM_ID,
        bundle_identifier=bundle_id,
        creation_date=now,
        expiration_date=now + timedelta(days=days),
        entitlements={
            "application-identifier": f"{TEAM_ID}.{bundle_id}",
            "get-task-allow": True,
        },
        device_ids=(UDID,),
        developer_certificates=(b"\x30\x82\x01\x00\x00\x00",),
        is_free=True,
        data=b"CMS-BYTES-" + uuid.encode("ascii"),
    )


def make_install_record(resigned: str = RESIGNED_ID) -> InstallRecord:
    return InstallRecord(
        original_bundle_id="com.example.nightly",
        resigned_bundle_id=resigned,
        app_id_identifier="APPID1",
        profile_uuid="PROFILE-UUID-1",
        dsid=DSID,
        udid=UDID,
        installed_at=datetime.now(UTC),
    )


def write_fake_ipa(path: Path, bundle_id: str = "com.example.nightly") -> Path:
    """A minimal but structurally real IPA: Payload/<app>/Info.plist."""
    import plistlib
    import zipfile

    info = plistlib.dumps(
        {"CFBundleIdentifier": bundle_id, "CFBundleExecutable": "Nightly"}
    )
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("Payload/Nightly.app/Info.plist", info)
        archive.writestr(
            "Payload/Nightly.app/Nightly", b"\xcf\xfa\xed\xfe" + b"\x00" * 28
        )
    return path


EXTRACTED_BUNDLES: list[FakeAppBundle] = []


def fake_extract_ipa(ipa_path: Path, dest_dir: Path | None = None) -> FakeIPABundle:
    root = Path(ipa_path).parent / "Payload" / "Nightly.app"
    bundle = FakeAppBundle(root, "com.example.nightly")
    EXTRACTED_BUNDLES.append(bundle)
    return FakeIPABundle(bundle)


def fake_repack_ipa(bundle: object, output_path: Path) -> Path:
    output = Path(output_path)
    output.write_bytes(b"signed-ipa-bytes")
    return output


def fake_build_entitlements(
    profile: ProvisioningProfile,
    original: dict[str, object] | None,
    extra: dict[str, object] | None,
    strict: bool,
) -> tuple[dict[str, object], list[str]]:
    dropped = ["com.apple.private.tcc"]
    if strict:
        raise errors.EntitlementsError(
            "the profile does not grant com.apple.private.tcc", dropped=dropped
        )
    merged: dict[str, object] = {
        "application-identifier": f"{TEAM_ID}.{RESIGNED_ID}",
        "get-task-allow": True,
    }
    return merged, dropped


def ideviceinfo_handler(
    values: dict[tuple[str | None, str], str],
) -> Callable[[list[str]], FakeResult]:
    """Script ideviceinfo keyed by (domain, key)."""

    def handle(cmd: list[str]) -> FakeResult:
        args = cmd[1:]

        def flag(name: str) -> str | None:
            return args[args.index(name) + 1] if name in args else None

        domain = flag("-q")
        key = flag("-k")
        if (domain, key) in values:
            return FakeResult(0, values[(domain, key)] + "\n")
        return FakeResult(0, "", "")

    return handle


def script_one_device(
    runner: FakeRunner,
    *,
    developer_mode: str = "Enabled",
    paired: bool = True,
) -> None:
    """Script a single healthy iPhone for the transport layer."""
    runner.script("idevice_id", FakeResult(0, UDID + "\n"))
    runner.script(
        "ideviceinfo",
        ideviceinfo_handler(
            {
                (None, "DeviceName"): "iPhone 12",
                (None, "ProductType"): "iPhone12,3",
                (None, "ProductVersion"): "17.6.1",
                (usbmux_mod.DEVELOPER_MODE_DOMAIN, usbmux_mod.DEVELOPER_MODE_KEY): developer_mode,
                ("com.apple.disk_usage", "TotalDataAvailable"): "127492296704",
                ("com.apple.disk_usage", "TotalDiskCapacity"): "512110190592",
            }
        ),
    )
    if paired:
        runner.script("idevicepair", FakeResult(0, f"SUCCESS: Validated pairing with device {UDID}\n"))
    else:
        runner.script("idevicepair", FakeResult(255, f"ERROR: Device {UDID} is not paired with this host\n"))


def script_installer(
    runner: FakeRunner,
    *,
    apps_stdout: str = "",
    install_rc: int = 0,
    install_stderr: str = "",
) -> None:
    """Script ideviceinstaller (version, list, install, uninstall)."""

    def handle(cmd: list[str]) -> FakeResult:
        if "--version" in cmd:
            return FakeResult(0, "ideviceinstaller 1.2.0\n")
        if "list" in cmd or "list_user" in cmd or "list_all" in cmd or "-l" in cmd:
            return FakeResult(0, apps_stdout)
        if "uninstall" in cmd or "-U" in cmd:
            return FakeResult(0, f"Uninstalling '{cmd[-1]}'\n\rUninstall: Complete\n")
        if install_rc != 0:
            return FakeResult(install_rc, "", install_stderr)
        return FakeResult(
            0,
            "Copying 'nightly.ipa' to device... DONE.\n"
            "Installing 'bundle'\n"
            "\rInstall: CreatingStagingDirectory (10%)"
            "\r\rInstall: ExtractingPackage (50%)"
            "\r\rInstall: VerifyingApplication"
            "\r\rInstall: Complete\n",
        )

    runner.script("ideviceinstaller", handle)


# ------------------------------------------------------------- fixtures


@pytest.fixture()
def home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    state = tmp_path / "state"
    monkeypatch.setenv(config.ENV_SIDELOAD_HOME, str(state))
    return state


@pytest.fixture()
def runner(monkeypatch: pytest.MonkeyPatch) -> FakeRunner:
    fake = FakeRunner()
    monkeypatch.setattr(usbmux_mod, "_run_subprocess", fake)
    monkeypatch.setattr(installer_mod, "_run_subprocess", fake)
    return fake


@pytest.fixture()
def fake_sign_stack(monkeypatch: pytest.MonkeyPatch, home: Path) -> None:
    """A logged in account plus in memory SIGN and AUTH doubles."""
    paths = config.get_paths()
    config.ensure_dirs(paths)
    config.save_config(paths, config.SideloadConfig(email=EMAIL))

    FakeKeychainStore.reset()
    FakeGrandSlam.reset()
    FakeDeveloperService.reset()
    FakeSigner.reset()
    EXTRACTED_BUNDLES.clear()

    monkeypatch.setattr(keychain_mod, "KeychainStore", FakeKeychainStore)
    monkeypatch.setattr(anisette_mod, "AnisetteProvider", FakeAnisette)
    monkeypatch.setattr(auth_mod, "GrandSlamClient", FakeGrandSlam)
    monkeypatch.setattr(developer_mod, "DeveloperServiceClient", FakeDeveloperService)

    monkeypatch.setattr(csr_mod, "generate_private_key", lambda: b"PRIVATE-KEY-PEM")
    monkeypatch.setattr(csr_mod, "make_machine_name", lambda: "MacBook-Pro-sideload")
    monkeypatch.setattr(csr_mod, "load_or_create_machine_id", lambda state_path: "MACHINE-ID")
    monkeypatch.setattr(csr_mod, "create_csr", lambda key_pem, machine_name: "CSR-PEM")
    monkeypatch.setattr(
        entitlements_mod,
        "read_entitlements",
        lambda macho_path: {"com.apple.private.tcc": True},
    )
    monkeypatch.setattr(entitlements_mod, "build_entitlements", fake_build_entitlements)
    monkeypatch.setattr(signer_mod, "KeychainSigner", FakeSigner)
    monkeypatch.setattr(
        profile_mod, "assert_profile_usable", lambda profile, udid, bundle_id: None
    )
    monkeypatch.setattr(ipa_mod, "extract_ipa", fake_extract_ipa)
    monkeypatch.setattr(
        ipa_mod,
        "resign_bundle_id",
        lambda original_bundle_id, team_identifier: f"{original_bundle_id}.{team_identifier.lower()}",
    )
    monkeypatch.setattr(ipa_mod, "repack_ipa", fake_repack_ipa)


# ------------------------------------------------------- parser surface


def test_help_works_for_every_command(capsys: pytest.CaptureFixture[str]) -> None:
    surfaces = [
        ["--help"],
        ["auth", "--help"],
        ["auth", "login", "--help"],
        ["auth", "status", "--help"],
        ["auth", "logout", "--help"],
        ["devices", "--help"],
        ["apps", "--help"],
        ["sign", "--help"],
        ["install", "--help"],
        ["uninstall", "--help"],
        ["doctor", "--help"],
    ]
    for argv in surfaces:
        with pytest.raises(SystemExit) as excinfo:
            main(argv)
        assert excinfo.value.code == 0
        capsys.readouterr()
    text = capsys.readouterr().out
    assert text == ""  # each surface printed and was consumed above


def test_help_text_lists_every_command(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--help"])
    assert excinfo.value.code == 0
    text = capsys.readouterr().out
    for command in ("auth", "login", "status", "logout", "devices", "apps", "sign", "install", "uninstall", "doctor"):
        assert command in text


def test_frozen_flag_surface() -> None:
    parser = build_parser()
    args = parser.parse_args(
        ["sign", "x.ipa", "--output", "o.ipa", "--bundle-id", "id", "--team", "T", "--strict-entitlements"]
    )
    assert args.command == "sign"
    assert args.output == "o.ipa"
    assert args.bundle_id == "id"
    assert args.team == "T"
    assert args.strict_entitlements is True
    args = parser.parse_args(["install", "x.ipa", "--udid", "U", "--team", "T"])
    assert args.command == "install"
    assert args.udid == "U"
    args = parser.parse_args(
        ["sign", "x.ipa", "--p12", "dev.p12", "--profile", "dev.mobileprovision"]
    )
    assert args.p12 == "dev.p12"
    assert args.profile == "dev.mobileprovision"
    args = parser.parse_args(
        ["install", "x.ipa", "--p12", "dev.p12", "--profile", "dev.mobileprovision"]
    )
    assert args.p12 == "dev.p12"
    assert args.profile == "dev.mobileprovision"
    args = parser.parse_args(["uninstall", "com.x", "--udid", "U", "--yes"])
    assert args.yes is True
    args = parser.parse_args(["auth", "login", "--email", "a@b.c", "--rotate-certificate"])
    assert args.email == "a@b.c"
    assert args.rotate_certificate is True
    args = parser.parse_args(["devices", "--udid", "U", "--pair"])
    assert args.pair is True
    args = parser.parse_args(["apps", "--all"])
    assert args.all is True
    args = parser.parse_args(["doctor", "--udid", "U", "--follow-logs"])
    assert args.follow_logs is True


@pytest.mark.parametrize(
    "argv",
    [[], ["bogus"], ["auth"], ["auth", "bogus"], ["sign"], ["uninstall"]],
)
def test_usage_errors_exit_2(argv: list[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(argv)
    assert excinfo.value.code == 2


def test_version_flag(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0
    assert "0.1.0" in capsys.readouterr().out


# ------------------------------------------------------- exit code paths


def test_uninstall_without_yes_exits_2(
    home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(["uninstall", "com.example.app"])
    assert code == 2
    captured = capsys.readouterr()
    assert "--yes" in captured.err


def test_uninstall_with_yes_but_no_device(
    home: Path, runner: FakeRunner, capsys: pytest.CaptureFixture[str]
) -> None:
    runner.script("idevice_id", FakeResult(0, ""))
    code = main(["uninstall", "com.example.app", "--yes"])
    assert code == 1
    assert "plug" in capsys.readouterr().err


def test_devices_none_connected_exit_1(
    home: Path, runner: FakeRunner, capsys: pytest.CaptureFixture[str]
) -> None:
    runner.script("idevice_id", FakeResult(0, ""))
    code = main(["devices"])
    assert code == 1
    captured = capsys.readouterr()
    assert "no USB device is connected" in captured.err
    assert "plug" in captured.err


def test_devices_listing_fields(
    home: Path, runner: FakeRunner, capsys: pytest.CaptureFixture[str]
) -> None:
    script_one_device(runner)
    code = main(["devices"])
    assert code == 0
    out = capsys.readouterr().out
    assert UDID in out
    assert "iPhone 12" in out
    assert "iPhone12,3" in out
    assert "iOS 17.6.1" in out
    assert "paired: yes" in out
    assert "developer mode: on" in out


def test_devices_pair_flow(
    home: Path, runner: FakeRunner, capsys: pytest.CaptureFixture[str]
) -> None:
    script_one_device(runner)
    runner.script("idevicepair", FakeResult(0, f"SUCCESS: Paired with device {UDID}\n"))
    code = main(["devices", "--pair"])
    assert code == 0
    out = capsys.readouterr().out
    assert "tap Trust on the device" in out
    assert "paired: yes" in out


def test_apps_listing(
    home: Path, runner: FakeRunner, capsys: pytest.CaptureFixture[str]
) -> None:
    script_one_device(runner)
    script_installer(
        runner,
        apps_stdout=(
            "CFBundleIdentifier, CFBundleShortVersionString, CFBundleDisplayName\n"
            "com.example.app, 1.2.3, Example App\n"
        ),
    )
    code = main(["apps"])
    assert code == 0
    out = capsys.readouterr().out
    assert "com.example.app - Example App (1.2.3)" in out


def test_apps_all_flag_runs_full_list(
    home: Path, runner: FakeRunner, capsys: pytest.CaptureFixture[str]
) -> None:
    script_one_device(runner)
    script_installer(runner, apps_stdout="")
    code = main(["apps", "--all"])
    assert code == 0
    list_call = next(call for call in runner.calls if "list" in call)
    assert list_call[1:] == ["-u", UDID, "list", "--all"]


def test_apps_unpaired_device_exit_1(
    home: Path, runner: FakeRunner, capsys: pytest.CaptureFixture[str]
) -> None:
    script_one_device(runner, paired=False)
    script_installer(runner)
    code = main(["apps"])
    assert code == 1
    captured = capsys.readouterr()
    assert "not paired" in captured.err
    assert "sideload devices --pair" in captured.err


def test_uninstall_full_flow_forgets_cache_record(
    home: Path, runner: FakeRunner, capsys: pytest.CaptureFixture[str]
) -> None:
    script_one_device(runner)
    script_installer(runner)
    paths = config.get_paths()
    config.ensure_dirs(paths)
    cache = cache_mod.ResourceCache(paths)
    cache.record_install(make_install_record())

    code = main(["uninstall", RESIGNED_ID, "--yes"])
    assert code == 0
    out = capsys.readouterr().out
    assert f"removed: {RESIGNED_ID}" in out
    assert cache.load_install_records(UDID) == []


# ------------------------------------------------------------ auth flows


def test_auth_status_missing_session_exit_3(
    home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(["auth", "status"])
    assert code == 3
    captured = capsys.readouterr()
    assert "sideload auth login" in captured.err


def test_auth_logout_nothing_stored_exit_0(
    home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(["auth", "logout"])
    assert code == 0
    assert "no stored session" in capsys.readouterr().out


def test_auth_login_flow(
    home: Path,
    runner: FakeRunner,
    fake_sign_stack: None,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(getpass, "getpass", lambda prompt: "hunter2-password")
    code = main(["auth", "login", "--email", EMAIL])
    assert code == 0
    captured = capsys.readouterr()
    out = captured.out
    assert "account: Test User" in out
    assert f"dsid: {DSID}" in out
    assert "team: Personal Team (free) id TEAMID1" in out
    assert "session expires:" in out
    # the password is never stored and never echoed
    assert "hunter2-password" not in out and "hunter2-password" not in captured.err
    assert [(email, session.dsid) for email, session in FakeKeychainStore.saved] == [(EMAIL, DSID)]
    paths = config.get_paths()
    assert config.load_config(paths).email == EMAIL


def test_auth_login_two_factor_three_attempts_then_exit_1(
    home: Path,
    runner: FakeRunner,
    fake_sign_stack: None,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        keychain_mod, "KeychainStore", FakeKeychainStore
    )  # keep the session store double
    monkeypatch.setattr(auth_mod, "GrandSlamClient", RejectingTwoFactorGrandSlam)
    monkeypatch.setattr(getpass, "getpass", lambda prompt: "hunter2-password")
    prompts: list[str] = []

    def fake_input(prompt: str = "") -> str:
        prompts.append(prompt)
        return "000000"

    monkeypatch.setattr("builtins.input", fake_input)
    code = main(["auth", "login", "--email", EMAIL])
    assert code == 1
    assert len(prompts) == 3
    captured = capsys.readouterr()
    assert "error:" in captured.err


def test_auth_status_happy_path(
    home: Path,
    runner: FakeRunner,
    fake_sign_stack: None,
    capsys: pytest.CaptureFixture[str],
) -> None:
    paths = config.get_paths()
    cache = cache_mod.ResourceCache(paths)
    cache.save_team(DSID, Team(identifier=TEAM_ID, name="Personal Team", team_type=TeamType.FREE))
    code = main(["auth", "status"])
    assert code == 0
    out = capsys.readouterr().out
    assert f"email: {EMAIL}" in out
    assert f"dsid: {DSID}" in out
    assert "token expiry:" in out
    assert "selected team: Personal Team (free) id TEAMID1" in out
    assert "tools:" in out
    assert "idevice_id" in out


def test_auth_logout_deletes_session(
    home: Path,
    runner: FakeRunner,
    fake_sign_stack: None,
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = main(["auth", "logout"])
    assert code == 0
    out = capsys.readouterr().out
    assert "cached profiles and App ID mirrors are kept" in out
    assert FakeKeychainStore.deleted == [EMAIL]
    paths = config.get_paths()
    assert config.load_config(paths).email is None


def test_stubbed_dependency_degrades_cleanly(
    home: Path,
    monkeypatch: pytest.MonkeyPatch,
    fake_sign_stack: None,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A component that is not implemented yet maps to a clean exit 1
    with a short message instead of a traceback.
    """
    def not_implemented(*args: object, **kwargs: object) -> None:
        raise NotImplementedError("unpacking")

    monkeypatch.setattr(ipa_mod, "extract_ipa", not_implemented)
    ipa = write_fake_ipa(tmp_path / "nightly.ipa")
    code = main(["sign", str(ipa)])
    assert code == 1
    captured = capsys.readouterr()
    assert "not implemented" in captured.err


# ------------------------------------------------------ config and cache


def test_get_paths_honors_side_load_home(home: Path) -> None:
    paths = config.get_paths()
    assert paths.root == home
    assert paths.accounts_dir == home / "accounts"
    assert paths.installs_dir == home / "installs"


def test_config_round_trip_and_permissions(home: Path) -> None:
    paths = config.get_paths()
    config.ensure_dirs(paths)
    settings = config.SideloadConfig(
        email=EMAIL,
        selected_team=TEAM_ID,
        default_device=UDID,
        rotate_certificate=True,
    )
    config.save_config(paths, settings)
    assert config.load_config(paths) == settings
    config_file = paths.root / "config.json"
    assert config_file.is_file()
    assert config_file.stat().st_mode & 0o777 == 0o600
    # atomic writes leave no temp files behind
    assert list(paths.root.glob("*.tmp")) == []
    assert list(paths.root.glob(".*tmp")) == []


def test_config_load_corrupt_file_yields_defaults(home: Path) -> None:
    paths = config.get_paths()
    config.ensure_dirs(paths)
    (paths.root / "config.json").write_text("{ not json", encoding="utf-8")
    assert config.load_config(paths) == config.SideloadConfig()


def test_ensure_dirs_permissions(home: Path) -> None:
    paths = config.get_paths()
    config.ensure_dirs(paths)
    for directory in (paths.root, paths.accounts_dir, paths.installs_dir, paths.logs_dir, paths.cache_dir):
        assert directory.is_dir()
        assert directory.stat().st_mode & 0o777 == 0o700


def test_find_tool_resolution() -> None:
    # the libimobiledevice tools are installed on this host (ACCEPTANCE.md
    # preconditions); a bogus name resolves to None.
    assert config.find_tool(config.TOOL_IDEVICE_ID) is not None
    assert config.find_tool("definitely-not-a-real-tool-xyz") is None
    tools = config.check_tools()
    assert config.TOOL_IDEVICE_ID in tools
    assert tools[config.TOOL_IDEVICE_ID] is not None


def test_cache_team_round_trip(home: Path) -> None:
    paths = config.get_paths()
    config.ensure_dirs(paths)
    cache = cache_mod.ResourceCache(paths)
    assert cache.load_team(DSID) is None
    team = Team(identifier=TEAM_ID, name="Personal Team", team_type=TeamType.FREE)
    cache.save_team(DSID, team)
    loaded = cache.load_team(DSID)
    assert loaded is not None
    assert loaded.identifier == TEAM_ID
    assert loaded.team_type is TeamType.FREE
    assert (paths.account_dir(DSID) / "team.json").stat().st_mode & 0o777 == 0o600


def test_cache_app_ids_round_trip(home: Path) -> None:
    paths = config.get_paths()
    config.ensure_dirs(paths)
    cache = cache_mod.ResourceCache(paths)
    assert cache.load_app_ids(DSID) == []
    app_ids = [
        AppIDRecord(identifier="A1", name="AppOne", bundle_identifier="com.one.app"),
        AppIDRecord(identifier="A2", name="AppTwo", bundle_identifier="com.two.app"),
    ]
    cache.save_app_ids(DSID, app_ids)
    assert cache.load_app_ids(DSID) == app_ids
    assert cache.find_app_id(DSID, "com.two.app") == app_ids[1]
    assert cache.find_app_id(DSID, "com.missing.app") is None


def test_cache_devices_round_trip(home: Path) -> None:
    paths = config.get_paths()
    config.ensure_dirs(paths)
    cache = cache_mod.ResourceCache(paths)
    devices = [DeviceRecord(name="iPhone", identifier=UDID)]
    cache.save_devices(DSID, devices)
    assert cache.load_devices(DSID) == devices


def test_cache_profile_round_trip(home: Path) -> None:
    paths = config.get_paths()
    config.ensure_dirs(paths)
    cache = cache_mod.ResourceCache(paths)
    profile = make_profile("UUID-1", RESIGNED_ID, days=7.0)
    cache.save_profile(DSID, profile)
    loaded = cache.load_profile(DSID, "UUID-1")
    assert loaded is not None
    assert loaded.uuid == "UUID-1"
    assert loaded.data == profile.data
    assert loaded.expiration_date == profile.expiration_date
    assert loaded.entitlements["application-identifier"] == f"{TEAM_ID}.{RESIGNED_ID}"
    assert cache.load_profile(DSID, "UUID-MISSING") is None
    assert cache.find_profile_for_bundle(DSID, RESIGNED_ID) is not None


def test_cache_expired_profile_is_never_reused(home: Path) -> None:
    """The 7 day wall: expired profiles are invisible to the freshness
    lookup so the next run re-downloads, but load still shows them.
    """
    paths = config.get_paths()
    config.ensure_dirs(paths)
    cache = cache_mod.ResourceCache(paths)
    cache.save_profile(DSID, make_profile("OLD", RESIGNED_ID, days=-1.0))
    assert cache.find_profile_for_bundle(DSID, RESIGNED_ID) is None
    assert cache.load_profile(DSID, "OLD") is not None


def test_cache_newest_fresh_profile_wins(home: Path) -> None:
    paths = config.get_paths()
    config.ensure_dirs(paths)
    cache = cache_mod.ResourceCache(paths)
    cache.save_profile(DSID, make_profile("P-3-DAYS", RESIGNED_ID, days=3.0))
    cache.save_profile(DSID, make_profile("P-6-DAYS", RESIGNED_ID, days=6.0))
    winner = cache.find_profile_for_bundle(DSID, RESIGNED_ID)
    assert winner is not None
    assert winner.uuid == "P-6-DAYS"


def test_cache_install_records_round_trip(home: Path) -> None:
    paths = config.get_paths()
    config.ensure_dirs(paths)
    cache = cache_mod.ResourceCache(paths)
    record = make_install_record()
    cache.record_install(record)
    newer = make_install_record()
    newer = InstallRecord(
        original_bundle_id=newer.original_bundle_id,
        resigned_bundle_id="com.example.other." + TEAM_ID.lower(),
        app_id_identifier=newer.app_id_identifier,
        profile_uuid=newer.profile_uuid,
        dsid=newer.dsid,
        udid=newer.udid,
        installed_at=newer.installed_at + timedelta(seconds=10.0),
    )
    cache.record_install(newer)
    records = cache.load_install_records(UDID)
    assert [r.resigned_bundle_id for r in records] == [newer.resigned_bundle_id, record.resigned_bundle_id]
    # a reinstall of the same bundle replaces, not duplicates
    again = make_install_record()
    cache.record_install(again)
    assert len(cache.load_install_records(UDID)) == 2
    cache.forget_install(UDID, record.resigned_bundle_id)
    assert [r.resigned_bundle_id for r in cache.load_install_records(UDID)] == [newer.resigned_bundle_id]


# ------------------------------------------------------- sign and install


def test_sign_full_flow(
    home: Path,
    runner: FakeRunner,
    fake_sign_stack: None,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ipa = write_fake_ipa(tmp_path / "nightly.ipa")
    output = tmp_path / "out" / "nightly.signed.ipa"
    code = main(["sign", str(ipa), "--output", str(output)])
    assert code == 0
    out = capsys.readouterr().out
    assert "team: Personal Team (free) id TEAMID1" in out
    assert "certificate: reused from the Keychain" in out
    assert "device registration: skipped (no device; sign only)" in out
    assert "app id: created (com.example.nightly.teamid1)" in out
    assert "profile expires:" in out
    assert "warning: entitlement 'com.apple.private.tcc' is not granted" in out
    assert "killed at launch by amfid" in out
    assert f"output: {output}" in out
    assert output.read_bytes() == b"signed-ipa-bytes"
    # the signer saw the entitlement set keyed by binary path
    assert FakeSigner.signed, "the signer was never invoked"
    _bundle, entitlements_by_path, identity = FakeSigner.signed[0]
    assert "Nightly" in entitlements_by_path
    assert identity.team_identifier == TEAM_ID


def test_sign_rewrites_bundle_id_and_embeds_profile(
    home: Path,
    runner: FakeRunner,
    fake_sign_stack: None,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ipa = write_fake_ipa(tmp_path / "nightly.ipa")
    code = main(["sign", str(ipa)])
    assert code == 0
    assert EXTRACTED_BUNDLES
    bundle = EXTRACTED_BUNDLES[-1]
    assert bundle.bundle_identifier == RESIGNED_ID
    assert bundle.embedded_profile == b"CMS-BYTES-PROFILE-UUID-1"


def test_sign_output_ipa_contains_rewritten_id_and_profile(
    home: Path,
    runner: FakeRunner,
    fake_sign_stack: None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import plistlib
    import zipfile

    monkeypatch.setattr(ipa_mod, "extract_ipa", REAL_EXTRACT_IPA)
    monkeypatch.setattr(ipa_mod, "repack_ipa", REAL_REPACK_IPA)
    ipa_path = write_fake_ipa(tmp_path / "nightly.ipa")
    code = main(["sign", str(ipa_path)])
    assert code == 0
    output = tmp_path / "nightly.signed.ipa"
    assert output.is_file()
    with zipfile.ZipFile(output) as archive:
        names = archive.namelist()
        info_name = next(name for name in names if name.endswith("Nightly.app/Info.plist"))
        info = plistlib.loads(archive.read(info_name))
        assert info["CFBundleIdentifier"] == RESIGNED_ID
        profile_name = next(
            name for name in names if name.endswith("Nightly.app/embedded.mobileprovision")
        )
        assert archive.read(profile_name) == b"CMS-BYTES-PROFILE-UUID-1"


def test_sign_provisions_each_extension_independently(
    home: Path,
    runner: FakeRunner,
    fake_sign_stack: None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    main_root = tmp_path / "Payload" / "Nightly.app"
    ext_root = main_root / "PlugIns" / "Share.appex"
    main_bundle = FakeAppBundle(main_root, "com.example.nightly")
    ext_bundle = FakeAppBundle(ext_root, "com.example.nightly.Share")
    bundle = FakeIPABundle(main_bundle)
    bundle.all_bundles = [ext_bundle, main_bundle]
    monkeypatch.setattr(
        ipa_mod, "extract_ipa", lambda ipa_path, dest_dir=None: bundle
    )
    ipa = write_fake_ipa(tmp_path / "nightly.ipa")
    code = main(["sign", str(ipa)])
    assert code == 0
    child_id = f"{RESIGNED_ID}.Share"
    assert ext_bundle.bundle_identifier == child_id
    assert ext_bundle.embedded_profile is not None
    assert child_id in FakeDeveloperService.created_app_ids
    out = capsys.readouterr().out
    assert f"extension: {child_id}" in out


def test_cached_profile_for_another_device_is_refreshed(
    home: Path,
    runner: FakeRunner,
    fake_sign_stack: None,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from dataclasses import replace

    paths = config.get_paths()
    cache = cache_mod.ResourceCache(paths)
    stale = replace(
        make_profile("STALE", RESIGNED_ID, days=7.0),
        device_ids=("00008101-000000000000000E",),
    )
    cache.save_profile(DSID, stale)
    script_one_device(runner)
    script_installer(runner)
    ipa = write_fake_ipa(tmp_path / "nightly.ipa")
    code = main(["install", str(ipa)])
    assert code == 0
    out = capsys.readouterr().out
    assert "no longer matches; refreshing" in out


def test_sign_default_output_name(
    home: Path,
    runner: FakeRunner,
    fake_sign_stack: None,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ipa = write_fake_ipa(tmp_path / "nightly.ipa")
    code = main(["sign", str(ipa)])
    assert code == 0
    out = capsys.readouterr().out
    assert f"output: {tmp_path / 'nightly.signed.ipa'}" in out
    assert (tmp_path / "nightly.signed.ipa").is_file()


def test_sign_strict_entitlements_exits_1(
    home: Path,
    runner: FakeRunner,
    fake_sign_stack: None,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ipa = write_fake_ipa(tmp_path / "nightly.ipa")
    code = main(["sign", str(ipa), "--strict-entitlements"])
    assert code == 1
    assert "error:" in capsys.readouterr().err


def test_sign_missing_session_exits_3(
    home: Path, runner: FakeRunner, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    ipa = write_fake_ipa(tmp_path / "nightly.ipa")
    code = main(["sign", str(ipa)])
    assert code == 3
    captured = capsys.readouterr()
    assert "sideload auth login" in captured.err


def test_sign_missing_ipa_exits_2(
    home: Path,
    runner: FakeRunner,
    fake_sign_stack: None,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = main(["sign", str(tmp_path / "nope.ipa")])
    assert code == 2
    assert "not found" in capsys.readouterr().err


def test_install_full_flow(
    home: Path,
    runner: FakeRunner,
    fake_sign_stack: None,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    script_one_device(runner)
    script_installer(runner)
    ipa = write_fake_ipa(tmp_path / "nightly.ipa")
    code = main(["install", str(ipa)])
    assert code == 0
    out = capsys.readouterr().out
    # the resign summary in the ACCEPTANCE order
    order = [
        "team: Personal Team (free) id TEAMID1",
        "certificate: reused from the Keychain",
        "device registration: done",
        "app id: created (com.example.nightly.teamid1)",
        "profile expires:",
        "warning: entitlement 'com.apple.private.tcc'",
        "CreatingStagingDirectory (10%)",
        "ExtractingPackage (50%)",
        "VerifyingApplication",
        f"installed: {RESIGNED_ID}",
    ]
    positions = [out.index(marker) for marker in order]
    assert positions == sorted(positions)
    # the device got the fresh install command, not upgrade
    signed = ipa.with_name(ipa.stem + ".signed.ipa")
    install_call = next(call for call in runner.calls if call[-1] == str(signed))
    assert install_call[1:] == ["-u", UDID, "install", str(signed)]
    # the install record is persisted for doctor and refreshes
    paths = config.get_paths()
    cache = cache_mod.ResourceCache(paths)
    records = cache.load_install_records(UDID)
    assert len(records) == 1
    assert records[0].resigned_bundle_id == RESIGNED_ID
    assert records[0].profile_uuid == "PROFILE-UUID-1"
    assert cache.find_profile_for_bundle(DSID, RESIGNED_ID) is not None
    # the device becomes the default target
    assert config.load_config(paths).default_device == UDID
    # the fresh profile was saved to disk under the account dir
    assert (paths.account_dir(DSID) / "profiles" / "PROFILE-UUID-1.mobileprovision").is_file()


def test_install_developer_mode_off_exits_1(
    home: Path,
    runner: FakeRunner,
    fake_sign_stack: None,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    script_one_device(runner, developer_mode="Disabled")
    script_installer(runner)
    ipa = write_fake_ipa(tmp_path / "nightly.ipa")
    code = main(["install", str(ipa)])
    assert code == 1
    captured = capsys.readouterr()
    assert "Developer Mode is off" in captured.err
    assert "Settings > Privacy and Security > Developer Mode" in captured.err


def test_install_unpaired_device_exits_1(
    home: Path,
    runner: FakeRunner,
    fake_sign_stack: None,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    script_one_device(runner, paired=False)
    script_installer(runner)
    ipa = write_fake_ipa(tmp_path / "nightly.ipa")
    code = main(["install", str(ipa)])
    assert code == 1
    captured = capsys.readouterr()
    assert "not paired" in captured.err
    assert "sideload devices --pair" in captured.err


def test_install_signature_failure_suggests_doctor_logs(
    home: Path,
    runner: FakeRunner,
    fake_sign_stack: None,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    script_one_device(runner)
    script_installer(
        runner,
        install_rc=255,
        install_stderr=(
            'ERROR: Install failed. Got error "ApplicationVerificationFailed" '
            "with code 0xe8008001: Failed to get code directory.\n"
        ),
    )
    ipa = write_fake_ipa(tmp_path / "nightly.ipa")
    code = main(["install", str(ipa)])
    assert code == 1
    captured = capsys.readouterr()
    assert "ApplicationVerificationFailed" in captured.err
    assert "hint:" in captured.err
    assert "sideload doctor --follow-logs" in captured.out
    # no install record for a failed install
    paths = config.get_paths()
    assert cache_mod.ResourceCache(paths).load_install_records(UDID) == []


def test_install_upgrade_command_when_already_installed(
    home: Path,
    runner: FakeRunner,
    fake_sign_stack: None,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    script_one_device(runner)
    script_installer(runner, apps_stdout=f"{RESIGNED_ID}, 1.0, Nightly\n")
    ipa = write_fake_ipa(tmp_path / "nightly.ipa", bundle_id=RESIGNED_ID)
    code = main(["install", str(ipa), "--udid", UDID])
    assert code == 0
    signed = ipa.with_name(ipa.stem + ".signed.ipa")
    upgrade_call = next(call for call in runner.calls if "upgrade" in call)
    assert upgrade_call[1:] == ["-u", UDID, "upgrade", str(signed)]
    assert f"installed: {RESIGNED_ID}" in capsys.readouterr().out


# ---------------------------------------------------------------- doctor


def test_doctor_report(
    home: Path,
    runner: FakeRunner,
    capsys: pytest.CaptureFixture[str],
) -> None:
    script_one_device(runner)
    script_installer(runner, apps_stdout="com.example.app, 1.0, App\n")
    runner.script("ideviceprovision", FakeResult(0, "Device has 1 provisioning profile installed:\nUUID1 - profile\n"))
    paths = config.get_paths()
    config.ensure_dirs(paths)
    cache = cache_mod.ResourceCache(paths)
    cache.record_install(make_install_record())

    code = main(["doctor"])
    assert code == 0
    out = capsys.readouterr().out
    assert "tools:" in out
    assert "pairing: yes" in out
    assert "developer mode: on" in out
    assert "free disk space: 127.5 GB of 512.1 GB" in out
    assert "device provisioning profiles: 1" in out
    assert "installed user apps: 1" in out
    assert "apps installed by sideload: 1" in out
    assert RESIGNED_ID in out


def test_doctor_no_device_still_prints_tools(
    home: Path, runner: FakeRunner, capsys: pytest.CaptureFixture[str]
) -> None:
    runner.script("idevice_id", FakeResult(0, ""))
    code = main(["doctor"])
    assert code == 0
    out = capsys.readouterr().out
    assert "tools:" in out
    assert "no USB device connected" in out


def test_doctor_follow_logs(
    home: Path,
    runner: FakeRunner,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    script_one_device(runner)
    script_installer(runner)
    monkeypatch.setattr(
        installer_mod,
        "_popen_subprocess",
        lambda cmd: FakePopen(["installd: staged\n", "noise\n", "amfid: rejected\n"]),
    )
    code = main(["doctor", "--follow-logs"])
    assert code == 0
    out = capsys.readouterr().out
    assert "installd: staged" in out
    assert "amfid: rejected" in out
    assert "noise" not in out


def test_doctor_follow_logs_without_device_exits_1(
    home: Path, runner: FakeRunner, capsys: pytest.CaptureFixture[str]
) -> None:
    runner.script("idevice_id", FakeResult(0, ""))
    code = main(["doctor", "--follow-logs"])
    assert code == 1
    assert "no USB device connected" in capsys.readouterr().err


def test_profile_covers_requires_the_current_certificate() -> None:
    from dataclasses import replace

    from sideload.cli import _profile_covers

    profile = make_profile("P1", RESIGNED_ID, days=7.0)
    team = Team(identifier=TEAM_ID, name="Personal Team", team_type=TeamType.FREE)
    der = b"\x30\x82\x01\x00\x00\x00"
    assert _profile_covers(profile, team, UDID, der)
    assert not _profile_covers(profile, team, UDID, b"another-certificate")
    other_device = replace(profile, device_ids=("00008101-000000000000000E",))
    assert not _profile_covers(other_device, team, UDID, der)


def test_install_without_session_exits_3_before_touching_device(
    home: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(["install", str(tmp_path / "nightly.ipa")])
    assert code == 3
    assert "sideload auth login" in capsys.readouterr().err


def test_corrupt_install_cache_is_quarantined(home: Path) -> None:
    paths = config.get_paths()
    config.ensure_dirs(paths)
    record_path = paths.install_records_path(UDID)
    record_path.write_text("{not json", encoding="utf-8")
    cache = cache_mod.ResourceCache(paths)
    assert cache.load_install_records(UDID) == []
    assert not record_path.exists()
    assert record_path.with_name(record_path.name + ".corrupt").exists()


def test_fresh_profile_without_the_current_certificate_is_rejected(
    home: Path,
    runner: FakeRunner,
    fake_sign_stack: None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from dataclasses import replace

    def fake_fetch(self, app_id, team):  # type: ignore[no-untyped-def]
        profile = make_profile("P-NOCERT", app_id.bundle_identifier, days=7.0)
        return replace(profile, developer_certificates=(b"another-certificate",))

    monkeypatch.setattr(FakeDeveloperService, "fetch_provisioning_profile", fake_fetch)
    ipa = write_fake_ipa(tmp_path / "nightly.ipa")
    code = main(["sign", str(ipa)])
    assert code == 1
    assert "does not include the current signing certificate" in capsys.readouterr().err


def test_corrupt_config_is_quarantined(home: Path) -> None:
    paths = config.get_paths()
    config.ensure_dirs(paths)
    config_file = paths.root / "config.json"
    config_file.write_text("{not json", encoding="utf-8")
    settings = config.load_config(paths)
    assert settings.email is None
    assert not config_file.exists()
    assert (paths.root / "config.json.corrupt").exists()


def test_sign_removes_artifacts_and_caches_the_new_app_id(
    home: Path,
    runner: FakeRunner,
    fake_sign_stack: None,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ipa = write_fake_ipa(tmp_path / "nightly.ipa")
    code = main(["sign", str(ipa)])
    assert code == 0
    assert EXTRACTED_BUNDLES[-1].artifacts_removed
    records = cache_mod.ResourceCache(config.get_paths()).load_app_ids(DSID)
    assert RESIGNED_ID in [record.bundle_identifier for record in records]
