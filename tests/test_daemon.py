"""Tests for the auto refresh slice: "sideload refresh", the "sideload
daemon" launchd agent, and the InstallRecord ipa_path cache field.

Every Apple, device, and launchd interaction is faked at the subprocess
or collaborator boundary: no network call, no device, no real launchctl,
and no write outside the SIDELOAD_HOME sandbox.
"""

from __future__ import annotations

import json
import os
import plistlib
import sys
import zipfile
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from sideload import cache as cache_mod
from sideload import config, errors
from sideload import daemon as daemon_mod
from sideload import keychain as keychain_mod
from sideload.apple import anisette as anisette_mod
from sideload.apple import auth as auth_mod
from sideload.apple import developer as developer_mod
from sideload.cli import main
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
from sideload.signing import profile as profile_mod
from sideload.signing import signer as signer_mod

UDID = "00008101-000000000000000E"
UDID2 = "00008101-000000000000000F"
EMAIL = "user@example.com"
DSID = "123456"
TEAM_ID = "TEAMID1"
RESIGNED_ID = "com.example.nightly.teamid1"
RESIGNED_ID2 = "com.example.other.teamid1"


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


class FakeKeychainStore:
    """In memory KeychainStore double."""

    def __init__(self) -> None:
        return None

    def load_session(self, email: str) -> AppleSession | None:
        return make_session(email)

    def save_session(self, email: str, session: AppleSession) -> None:
        return None

    def delete_session(self, email: str) -> bool:
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
    """AnisetteProvider double."""

    def get_anisette(self) -> None:
        return None


class FakeDeveloperService:
    """DeveloperServiceClient double with per class state so resource
    reuse across separate sign pipeline runs (install, then refresh)
    is observable.
    """

    registered: list[DeviceRecord] = []  # noqa: RUF012 - shared fake state
    created_app_ids: list[str] = []  # noqa: RUF012 - shared fake state
    profile_counter: int = 0
    fetch_teams_calls: int = 0

    def __init__(self, session: AppleSession, anisette: object) -> None:
        self.session = session
        self.anisette = anisette

    @classmethod
    def reset(cls) -> None:
        cls.registered = []
        cls.created_app_ids = []
        cls.profile_counter = 0
        cls.fetch_teams_calls = 0

    def fetch_teams(self) -> list[Team]:
        FakeDeveloperService.fetch_teams_calls += 1
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
        self, csr_pem: str, machine_name: str, team: Team, machine_id: str | None = None
    ) -> object:
        raise AssertionError("the fake identity is reused; no CSR should be submitted")

    def revoke_certificate(self, certificate: object, team: Team) -> None:
        return None

    def fetch_app_ids(self, team: Team) -> list[AppIDRecord]:
        return [
            AppIDRecord(identifier="APPID1", name=bundle_id, bundle_identifier=bundle_id)
            for bundle_id in FakeDeveloperService.created_app_ids
        ]

    def add_app_id(self, name: str, bundle_identifier: str, team: Team) -> AppIDRecord:
        FakeDeveloperService.created_app_ids.append(bundle_identifier)
        return AppIDRecord(
            identifier="APPID1", name=name, bundle_identifier=bundle_identifier
        )

    def fetch_provisioning_profile(self, app_id: AppIDRecord, team: Team) -> ProvisioningProfile:
        FakeDeveloperService.profile_counter += 1
        return make_profile(
            f"PROFILE-NEW-{FakeDeveloperService.profile_counter}",
            app_id.bundle_identifier,
            days=7.0,
        )


class RejectingSessionDeveloperService(FakeDeveloperService):
    """Apple rejects the stored session on the first developer call."""

    def fetch_teams(self) -> list[Team]:
        FakeDeveloperService.fetch_teams_calls += 1
        raise errors.SessionExpiredError(
            "Apple rejected the stored session; it has expired or been revoked.",
            hint="run: sideload auth login",
        )


class FakeSigner:
    """KeychainSigner double recording sign calls."""

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


def make_install_record(
    resigned: str = RESIGNED_ID,
    udid: str = UDID,
    ipa_path: str | None = None,
    profile_uuid: str = "PROFILE-OLD",
) -> InstallRecord:
    return InstallRecord(
        original_bundle_id="com.example." + resigned.removesuffix("." + TEAM_ID.lower()),
        resigned_bundle_id=resigned,
        app_id_identifier="APPID1",
        profile_uuid=profile_uuid,
        dsid=DSID,
        udid=udid,
        installed_at=datetime.now(UTC),
        ipa_path=ipa_path,
    )


def write_fake_ipa(path: Path, bundle_id: str = "com.example.nightly") -> Path:
    """A minimal but structurally real IPA: Payload/<app>/Info.plist."""
    import plistlib

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
    merged: dict[str, object] = {
        "application-identifier": f"{TEAM_ID}.{profile.bundle_identifier}",
        "get-task-allow": True,
    }
    return merged, []


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
    udid: str = UDID,
    developer_mode: str = "Enabled",
    paired: bool = True,
) -> None:
    """Script one healthy iPhone for the transport layer."""
    runner.script("idevice_id", FakeResult(0, udid + "\n"))
    runner.script(
        "ideviceinfo",
        ideviceinfo_handler(
            {
                (None, "DeviceName"): "iPhone 12",
                (None, "ProductType"): "iPhone12,3",
                (None, "ProductVersion"): "17.6.1",
                (usbmux_mod.DEVELOPER_MODE_DOMAIN, usbmux_mod.DEVELOPER_MODE_KEY): developer_mode,
            }
        ),
    )
    if paired:
        runner.script("idevicepair", FakeResult(0, f"SUCCESS: Validated pairing with device {udid}\n"))
    else:
        runner.script(
            "idevicepair", FakeResult(255, f"ERROR: Device {udid} is not paired with this host\n")
        )


def script_installer(
    runner: FakeRunner,
    *,
    apps_stdout: str = "",
    install_handler: Callable[[list[str]], FakeResult] | None = None,
) -> None:
    """Script ideviceinstaller (version, list, install)."""

    def handle(cmd: list[str]) -> FakeResult:
        if "--version" in cmd:
            return FakeResult(0, "ideviceinstaller 1.2.0\n")
        if "list" in cmd or "list_user" in cmd or "list_all" in cmd or "-l" in cmd:
            return FakeResult(0, apps_stdout)
        if install_handler is not None:
            return install_handler(cmd)
        return FakeResult(0, "Install: Complete\n")

    runner.script("ideviceinstaller", handle)


def launchctl_handler(
    *,
    loaded: bool = False,
    bootstrap_rc: int = 0,
    load_rc: int = 0,
    bootout_rc: int = 0,
) -> Callable[[list[str]], FakeResult]:
    """Script launchctl by subcommand."""

    def handle(cmd: list[str]) -> FakeResult:
        sub = cmd[1] if len(cmd) > 1 else ""
        if sub == "list":
            return FakeResult(0 if loaded else 1, "", "")
        if sub == "bootstrap":
            return FakeResult(bootstrap_rc, "", "" if bootstrap_rc == 0 else "bootstrap refused")
        if sub == "load":
            return FakeResult(load_rc, "", "")
        if sub == "bootout":
            return FakeResult(bootout_rc, "", "")
        return FakeResult(0, "", "")

    return handle


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
def launchctl(monkeypatch: pytest.MonkeyPatch) -> FakeRunner:
    fake = FakeRunner()
    monkeypatch.setattr(daemon_mod, "_run_launchctl", fake)
    return fake


@pytest.fixture()
def fake_sign_stack(monkeypatch: pytest.MonkeyPatch, home: Path) -> None:
    """A logged in account plus in memory SIGN and AUTH doubles."""
    paths = config.get_paths()
    config.ensure_dirs(paths)
    config.save_config(paths, config.SideloadConfig(email=EMAIL))

    FakeDeveloperService.reset()
    FakeSigner.reset()
    EXTRACTED_BUNDLES.clear()

    monkeypatch.setattr(keychain_mod, "KeychainStore", FakeKeychainStore)
    monkeypatch.setattr(anisette_mod, "AnisetteProvider", FakeAnisette)
    monkeypatch.setattr(auth_mod, "GrandSlamClient", object)
    monkeypatch.setattr(developer_mod, "DeveloperServiceClient", FakeDeveloperService)

    monkeypatch.setattr(csr_mod, "generate_private_key", lambda: b"PRIVATE-KEY-PEM")
    monkeypatch.setattr(csr_mod, "make_machine_name", lambda: "MacBook-Pro-sideload")
    monkeypatch.setattr(csr_mod, "load_or_create_machine_id", lambda state_path: "MACHINE-ID")
    monkeypatch.setattr(csr_mod, "create_csr", lambda key_pem, machine_name: "CSR-PEM")
    monkeypatch.setattr(
        entitlements_mod,
        "read_entitlements",
        lambda macho_path: {},
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


def record_two_apps(cache: cache_mod.ResourceCache, tmp_path: Path) -> tuple[Path, Path]:
    """Two install records on one device: a refreshable source IPA and
    a missing one.
    """
    good = write_fake_ipa(tmp_path / "nightly.ipa")
    gone = tmp_path / "gone.ipa"
    cache.record_install(make_install_record(RESIGNED_ID, ipa_path=str(good)))
    cache.record_install(
        make_install_record(RESIGNED_ID2, ipa_path=str(gone), profile_uuid="PROFILE-GONE")
    )
    return good, gone


# ------------------------------------------------------- parser surface


def test_help_surfaces_for_refresh_and_daemon(capsys: pytest.CaptureFixture[str]) -> None:
    surfaces = [
        ["refresh", "--help"],
        ["daemon", "--help"],
        ["daemon", "install", "--help"],
        ["daemon", "uninstall", "--help"],
        ["daemon", "status", "--help"],
    ]
    for argv in surfaces:
        with pytest.raises(SystemExit) as excinfo:
            main(argv)
        assert excinfo.value.code == 0
        capsys.readouterr()


def test_refresh_flag_surface() -> None:
    from sideload.cli import build_parser

    parser = build_parser()
    args = parser.parse_args(["refresh"])
    assert args.command == "refresh"
    assert args.udid is None
    assert args.all is False
    args = parser.parse_args(["refresh", "--udid", "U", "--all"])
    assert args.udid == "U"
    assert args.all is True
    args = parser.parse_args(["daemon", "install"])
    assert args.command == "daemon"
    assert args.daemon_command == "install"


def test_daemon_without_subcommand_exits_2() -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["daemon"])
    assert excinfo.value.code == 2


def test_refresh_all_and_udid_together_exits_2(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["refresh", "--all", "--udid", "U"])
    assert code == 2
    assert "mutually exclusive" in capsys.readouterr().err


# ------------------------------------------------------- refresh command


def test_refresh_one_success_one_missing_ipa(
    home: Path,
    runner: FakeRunner,
    fake_sign_stack: None,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Two records: one re-signs and reinstalls, one has no source IPA.
    The summary reports both and the run exits 0 because every
    attempted app succeeded.
    """
    script_one_device(runner)
    script_installer(runner)
    cache = cache_mod.ResourceCache(config.get_paths())
    good, gone = record_two_apps(cache, tmp_path)

    code = main(["refresh"])
    assert code == 0
    out = capsys.readouterr().out
    # the record's resigned bundle id is reused, not recomputed
    assert f"bundle id: com.example.nightly -> {RESIGNED_ID}" in out
    assert f"refreshed: {RESIGNED_ID} - re-signed from {good}" in out
    assert f"skipped: {RESIGNED_ID2} - source IPA not found: {gone}" in out
    assert "refresh summary:" in out
    assert "refreshed 1, skipped 1, failed 0" in out
    # exactly one sign attempt, for the record that still has its IPA
    assert len(FakeSigner.signed) == 1
    install_calls = [call for call in runner.calls if call[-1].endswith(".refresh.ipa")]
    assert len(install_calls) == 1
    assert install_calls[0][1:3] == ["-u", UDID]
    # the refreshed record got the new profile uuid; the skipped record
    # was kept untouched, not deleted
    records = {
        record.resigned_bundle_id: record
        for record in cache.load_install_records(UDID)
    }
    assert records[RESIGNED_ID].profile_uuid == "PROFILE-NEW-1"
    assert records[RESIGNED_ID2].profile_uuid == "PROFILE-GONE"


def test_refresh_missing_session_exits_3_before_any_sign(
    home: Path,
    runner: FakeRunner,
    fake_sign_stack: None,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cache = cache_mod.ResourceCache(config.get_paths())
    record_two_apps(cache, tmp_path)
    config.save_config(config.get_paths(), config.SideloadConfig(email=None))

    code = main(["refresh"])
    assert code == 3
    captured = capsys.readouterr()
    assert "run: sideload auth login" in captured.err
    assert FakeSigner.signed == []
    assert FakeDeveloperService.fetch_teams_calls == 0


def test_refresh_apple_rejected_session_exits_3_on_first_call(
    home: Path,
    runner: FakeRunner,
    fake_sign_stack: None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A rejected session stops the whole run: no Apple call beyond the
    first failure, no second sign attempt.
    """
    monkeypatch.setattr(
        developer_mod, "DeveloperServiceClient", RejectingSessionDeveloperService
    )
    script_one_device(runner)
    script_installer(runner)
    cache = cache_mod.ResourceCache(config.get_paths())
    record_two_apps(cache, tmp_path)

    code = main(["refresh", "--udid", UDID])
    assert code == 3
    captured = capsys.readouterr()
    assert "sideload auth login" in captured.err
    assert "refresh stopped" in captured.out
    # the very first developer call (fetch_teams) was the only one
    assert FakeDeveloperService.fetch_teams_calls == 1
    assert FakeSigner.signed == []


def test_refresh_device_not_connected(
    home: Path,
    runner: FakeRunner,
    fake_sign_stack: None,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    runner.script("idevice_id", FakeResult(0, ""))
    cache = cache_mod.ResourceCache(config.get_paths())
    record_two_apps(cache, tmp_path)

    code = main(["refresh", "--udid", UDID])
    assert code == 1
    out = capsys.readouterr().out
    assert f"skipping device {UDID}: it is not connected over USB" in out
    assert "refresh summary:" in out
    assert "refreshed 0, skipped 2, failed 0" in out
    assert FakeSigner.signed == []


def test_refresh_unpaired_device_skipped(
    home: Path,
    runner: FakeRunner,
    fake_sign_stack: None,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    script_one_device(runner, paired=False)
    script_installer(runner)
    cache = cache_mod.ResourceCache(config.get_paths())
    record_two_apps(cache, tmp_path)

    code = main(["refresh", "--udid", UDID])
    assert code == 1
    out = capsys.readouterr().out
    assert f"skipping device {UDID}: it is not paired" in out
    assert FakeSigner.signed == []


def test_refresh_developer_mode_off_skips_device(
    home: Path,
    runner: FakeRunner,
    fake_sign_stack: None,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    script_one_device(runner, developer_mode="Disabled")
    script_installer(runner)
    cache = cache_mod.ResourceCache(config.get_paths())
    record_two_apps(cache, tmp_path)

    code = main(["refresh", "--udid", UDID])
    assert code == 1
    out = capsys.readouterr().out
    assert f"skipping device {UDID}: Developer Mode is off" in out
    assert "Settings > Privacy and Security > Developer Mode" in out
    assert FakeSigner.signed == []


def test_refresh_all_with_second_device_offline(
    home: Path,
    runner: FakeRunner,
    fake_sign_stack: None,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """--all refreshes every device with records; the offline device is
    skipped without failing the run.
    """
    script_one_device(runner)
    script_installer(runner)
    cache = cache_mod.ResourceCache(config.get_paths())
    good = write_fake_ipa(tmp_path / "nightly.ipa")
    cache.record_install(make_install_record(RESIGNED_ID, ipa_path=str(good)))
    cache.record_install(
        make_install_record(RESIGNED_ID, udid=UDID2, ipa_path=str(good))
    )

    code = main(["refresh", "--all"])
    assert code == 0
    out = capsys.readouterr().out
    assert f"skipping device {UDID2}: it is not connected over USB" in out
    assert "refreshed 1, skipped 1, failed 0" in out
    # the offline device was never probed further
    assert all(UDID2 not in " ".join(call) for call in runner.calls)


def test_refresh_install_failure_fails_the_run_but_not_the_other_app(
    home: Path,
    runner: FakeRunner,
    fake_sign_stack: None,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    script_one_device(runner)

    def install_handler(cmd: list[str]) -> FakeResult:
        if "nightly" in cmd[-1]:
            return FakeResult(
                255,
                "",
                'ERROR: Install failed. Got error "ApplicationVerificationFailed" '
                "with code 0xe8008001: Failed to get code directory.\n",
            )
        return FakeResult(0, "Install: Complete\n")

    script_installer(runner, install_handler=install_handler)
    cache = cache_mod.ResourceCache(config.get_paths())
    good = write_fake_ipa(tmp_path / "nightly.ipa")
    other = write_fake_ipa(tmp_path / "other.ipa")
    cache.record_install(make_install_record(RESIGNED_ID, ipa_path=str(good)))
    cache.record_install(make_install_record(RESIGNED_ID2, ipa_path=str(other)))

    code = main(["refresh", "--udid", UDID])
    assert code == 1
    out = capsys.readouterr().out
    assert "run: sideload doctor --follow-logs" in out
    assert (
        f"failed: {RESIGNED_ID} - Install failed: ApplicationVerificationFailed"
        in out
    )
    assert f"refreshed: {RESIGNED_ID2}" in out
    assert "refreshed 1, skipped 0, failed 1" in out
    # the failed app kept its old record; the successful one moved on
    records = {record.resigned_bundle_id: record for record in cache.load_install_records(UDID)}
    assert records[RESIGNED_ID].profile_uuid == "PROFILE-OLD"
    assert records[RESIGNED_ID2].profile_uuid.startswith("PROFILE-NEW-")


def test_refresh_record_without_recorded_ipa_is_skipped(
    home: Path,
    runner: FakeRunner,
    fake_sign_stack: None,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Old records (written before the ipa_path field) load fine and are
    reported, skipped, and kept.
    """
    script_one_device(runner)
    script_installer(runner)
    cache = cache_mod.ResourceCache(config.get_paths())
    cache.record_install(make_install_record(RESIGNED_ID, ipa_path=None))

    code = main(["refresh", "--udid", UDID])
    assert code == 1
    out = capsys.readouterr().out
    assert "no source IPA is recorded" in out
    assert "sideload install <ipa>" in out
    assert "refreshed 0, skipped 1, failed 0" in out
    assert FakeSigner.signed == []
    assert len(cache.load_install_records(UDID)) == 1


def test_refresh_no_records_exits_1(
    home: Path,
    runner: FakeRunner,
    fake_sign_stack: None,
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = main(["refresh", "--all"])
    assert code == 1
    assert "no install records found" in capsys.readouterr().out


def test_install_records_the_source_ipa_then_refresh_reuses_everything(
    home: Path,
    runner: FakeRunner,
    fake_sign_stack: None,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Install persists the absolute source IPA path; a later refresh
    reuses the cached team, device registration, App ID, and profile
    instead of re-creating them.
    """
    script_one_device(runner)
    script_installer(runner)
    ipa = write_fake_ipa(tmp_path / "nightly.ipa")

    assert main(["install", str(ipa)]) == 0
    cache = cache_mod.ResourceCache(config.get_paths())
    (record,) = cache.load_install_records(UDID)
    assert record.ipa_path == str(ipa.resolve())

    capsys.readouterr()  # drop the install output
    code = main(["refresh"])
    assert code == 0
    out = capsys.readouterr().out
    assert "device registration: reused" in out
    assert f"app id: reused ({RESIGNED_ID})" in out
    assert "profile: reused" in out
    assert f"refreshed: {RESIGNED_ID}" in out
    assert "refreshed 1, skipped 0, failed 0" in out
    # the refreshed install ran over the temp re-signed output
    install_calls = [
        call
        for call in runner.calls
        if "install" in call and call[-1].endswith(".refresh.ipa")
    ]
    assert install_calls
    assert install_calls[0][1] == "-u"


# ------------------------------------------------------------ cache field


def test_cache_loads_old_install_record_without_ipa_path(home: Path) -> None:
    """Records serialized before the refresh feature exist must load
    with ipa_path None instead of failing.
    """
    paths = config.get_paths()
    config.ensure_dirs(paths)
    record_path = paths.install_records_path(UDID)
    record_path.write_text(
        json.dumps(
            [
                {
                    "original_bundle_id": "com.example.nightly",
                    "resigned_bundle_id": RESIGNED_ID,
                    "app_id_identifier": "APPID1",
                    "profile_uuid": "PROFILE-UUID-1",
                    "dsid": DSID,
                    "udid": UDID,
                    "installed_at": "2024-05-01T10:00:00+00:00",
                }
            ]
        ),
        encoding="utf-8",
    )
    records = cache_mod.ResourceCache(paths).load_install_records(UDID)
    assert len(records) == 1
    assert records[0].ipa_path is None
    assert records[0].resigned_bundle_id == RESIGNED_ID
    assert records[0].installed_at.year == 2024


def test_cache_round_trips_ipa_path_and_groups_all_devices(home: Path) -> None:
    paths = config.get_paths()
    config.ensure_dirs(paths)
    cache = cache_mod.ResourceCache(paths)
    ipa = write_fake_ipa(paths.root / "nightly.ipa")
    cache.record_install(make_install_record(RESIGNED_ID, ipa_path=str(ipa)))
    cache.record_install(
        make_install_record(RESIGNED_ID2, udid=UDID2, ipa_path=str(ipa))
    )

    (record,) = cache.load_install_records(UDID)
    assert record.ipa_path == str(ipa)
    grouped = cache.load_all_install_records()
    assert set(grouped) == {UDID, UDID2}
    assert grouped[UDID][0].resigned_bundle_id == RESIGNED_ID
    assert grouped[UDID2][0].resigned_bundle_id == RESIGNED_ID2


# ------------------------------------------------------- launchd agent


def plist_path_of(home: Path) -> Path:
    return (
        Path(home)
        / "Library"
        / "LaunchAgents"
        / daemon_mod.PLIST_FILE_NAME
    )


def test_daemon_install_writes_plist_and_bootstraps(
    home: Path,
    launchctl: FakeRunner,
    capsys: pytest.CaptureFixture[str],
) -> None:
    launchctl.script("launchctl", launchctl_handler(loaded=False))

    code = main(["daemon", "install"])
    assert code == 0
    plist_file = plist_path_of(home)
    assert plist_file.is_file()
    # 0700 directory, 0600 file, no temp leftovers
    assert plist_file.parent.stat().st_mode & 0o777 == 0o700
    assert plist_file.stat().st_mode & 0o777 == 0o600
    plist = plistlib.loads(plist_file.read_bytes())
    assert plist["Label"] == daemon_mod.LAUNCH_AGENT_LABEL
    assert plist["ProgramArguments"] == [
        sys.executable,
        "-m",
        "sideload",
        "refresh",
        "--all",
    ]
    assert plist["StartInterval"] == daemon_mod.START_INTERVAL_SECONDS == 86400
    assert plist["RunAtLoad"] is False
    log_path = Path(home) / "logs" / "refresh.log"
    assert plist["StandardOutPath"] == str(log_path)
    assert plist["StandardErrorPath"] == str(log_path)
    assert log_path.parent.is_dir()
    # the modern bootstrap was invoked through the injected runner
    assert launchctl.calls == [
        ["launchctl", "list", daemon_mod.LAUNCH_AGENT_LABEL],
        ["launchctl", "bootstrap", f"gui/{os.getuid()}", str(plist_file)],
    ]
    out = capsys.readouterr().out
    assert f"launch agent: {plist_file}" in out
    assert "remove it with: sideload daemon uninstall" in out
    assert "never prompts" in out


def test_daemon_install_replaces_a_loaded_agent(
    home: Path, launchctl: FakeRunner
) -> None:
    launchctl.script("launchctl", launchctl_handler(loaded=True))
    code = main(["daemon", "install"])
    assert code == 0
    subcommands = [call[1] for call in launchctl.calls]
    assert subcommands == ["list", "bootout", "bootstrap"]


def test_daemon_install_falls_back_to_legacy_load(
    home: Path, launchctl: FakeRunner
) -> None:
    launchctl.script(
        "launchctl", launchctl_handler(loaded=False, bootstrap_rc=5, load_rc=0)
    )
    code = main(["daemon", "install"])
    assert code == 0
    assert launchctl.calls[-1] == ["launchctl", "load", str(plist_path_of(home))]


def test_daemon_install_failure_exits_1(
    home: Path, launchctl: FakeRunner, capsys: pytest.CaptureFixture[str]
) -> None:
    launchctl.script(
        "launchctl",
        launchctl_handler(loaded=False, bootstrap_rc=5, load_rc=5),
    )
    code = main(["daemon", "install"])
    assert code == 1
    captured = capsys.readouterr()
    assert "launchctl could not load the refresh agent" in captured.err
    assert "bootstrap" in captured.err
    # the plist is still on disk; only the launch step failed
    assert plist_path_of(home).is_file()


def test_daemon_uninstall_boots_out_and_removes_plist(
    home: Path, launchctl: FakeRunner, capsys: pytest.CaptureFixture[str]
) -> None:
    launchctl.script("launchctl", launchctl_handler(loaded=True))
    assert main(["daemon", "install"]) == 0
    plist_file = plist_path_of(home)
    assert plist_file.is_file()
    capsys.readouterr()

    launchctl.calls.clear()
    code = main(["daemon", "uninstall"])
    assert code == 0
    assert not plist_file.exists()
    assert ["launchctl", "bootout", f"gui/{os.getuid()}/{daemon_mod.LAUNCH_AGENT_LABEL}"]
    in_list = [call for call in launchctl.calls if call[1] == "bootout"]
    assert in_list == [
        ["launchctl", "bootout", f"gui/{os.getuid()}/{daemon_mod.LAUNCH_AGENT_LABEL}"]
    ]
    out = capsys.readouterr().out
    assert f"removed: {plist_file}" in out


def test_daemon_uninstall_without_plist_is_not_an_error(
    home: Path, launchctl: FakeRunner, capsys: pytest.CaptureFixture[str]
) -> None:
    launchctl.script("launchctl", launchctl_handler(loaded=False))
    code = main(["daemon", "uninstall"])
    assert code == 0
    out = capsys.readouterr().out
    assert "no launch agent plist" in out
    assert "unloaded" in out


def test_daemon_status_reports_file_and_launchd(
    home: Path, launchctl: FakeRunner, capsys: pytest.CaptureFixture[str]
) -> None:
    # installed and loaded
    launchctl.script("launchctl", launchctl_handler(loaded=False))
    assert main(["daemon", "install"]) == 0
    capsys.readouterr()
    launchctl.calls.clear()
    launchctl.script("launchctl", launchctl_handler(loaded=True))
    assert main(["daemon", "status"]) == 0
    out = capsys.readouterr().out
    assert "plist: present" in out
    assert "agent: loaded" in out

    # not installed at all
    launchctl.script("launchctl", launchctl_handler(loaded=False))
    assert main(["daemon", "uninstall"]) == 0
    capsys.readouterr()
    assert main(["daemon", "status"]) == 0
    out = capsys.readouterr().out
    assert "plist: missing" in out
    assert "agent: not loaded" in out
    assert f"log: {Path(home) / 'logs' / 'refresh.log'}" in out


def test_refresh_daemon_accepts_injected_paths_runner_and_uid(tmp_path: Path) -> None:
    """The launchd plumbing is fully injectable: tests never touch the
    real ~/Library or the real launchd.
    """
    calls: list[list[str]] = []

    def fake_runner(cmd: Sequence[str], timeout: float | None = None) -> FakeResult:
        calls.append(list(cmd))
        if list(cmd)[1:2] == ["list"]:
            return FakeResult(1, "", "")
        return FakeResult(0, "", "")

    paths = daemon_mod.DaemonPaths(
        plist_path=tmp_path / "agents" / daemon_mod.PLIST_FILE_NAME,
        log_path=tmp_path / "logs" / "refresh.log",
    )
    agent = daemon_mod.RefreshDaemon(paths=paths, runner=fake_runner, uid=501)

    written = agent.install(
        program_arguments=["/usr/bin/python3", "-m", "sideload", "refresh", "--all"]
    )
    assert written == paths.plist_path
    assert calls == [
        ["launchctl", "list", daemon_mod.LAUNCH_AGENT_LABEL],
        ["launchctl", "bootstrap", "gui/501", str(paths.plist_path)],
    ]
    plist = plistlib.loads(paths.plist_path.read_bytes())
    assert plist["ProgramArguments"][0] == "/usr/bin/python3"
    assert plist["RunAtLoad"] is False

    status = agent.status()
    assert status.plist_exists is True
    assert status.loaded is False

    assert agent.uninstall() is True
    assert not paths.plist_path.exists()
    assert not agent.status().plist_exists


def test_build_refresh_plist_shape(tmp_path: Path) -> None:
    plist = daemon_mod.build_refresh_plist(
        ["python3", "-m", "sideload", "refresh", "--all"],
        tmp_path / "refresh.log",
        start_interval=3600,
    )
    assert plist == {
        "Label": daemon_mod.LAUNCH_AGENT_LABEL,
        "ProgramArguments": ["python3", "-m", "sideload", "refresh", "--all"],
        "StartInterval": 3600,
        "RunAtLoad": False,
        "StandardOutPath": str(tmp_path / "refresh.log"),
        "StandardErrorPath": str(tmp_path / "refresh.log"),
    }
    assert daemon_mod.refresh_program_arguments()[1:] == ["-m", "sideload", "refresh", "--all"]


def test_unattended_refresh_refuses_pending_certificate_rotation() -> None:
    from sideload import config
    from sideload.daemon import assert_no_pending_rotation

    assert_no_pending_rotation(config.SideloadConfig())
    with pytest.raises(errors.DaemonError) as excinfo:
        assert_no_pending_rotation(config.SideloadConfig(rotate_certificate=True))
    assert "rotation" in str(excinfo.value).lower()
