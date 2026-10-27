"""Tests for the device slice: usbmux transport and installer client.

Every device interaction is faked at the subprocess boundary (the
module level _run_subprocess / _popen_subprocess indirections), so no
test in this file can ever reach a real iPhone.
"""

from __future__ import annotations

import io
from collections.abc import Callable, Sequence
from pathlib import Path

import pytest

from sideload import config, errors
from sideload.device import installer, usbmux
from sideload.models import IOSDevice

UDID = "00008101-000000000000000E"
UDID2 = "00008101-000000000000000D"


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


@pytest.fixture()
def runner(monkeypatch: pytest.MonkeyPatch) -> FakeRunner:
    fake = FakeRunner()
    monkeypatch.setattr(usbmux, "_run_subprocess", fake)
    monkeypatch.setattr(installer, "_run_subprocess", fake)
    return fake


@pytest.fixture()
def home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    state = tmp_path / "state"
    monkeypatch.setenv(config.ENV_SIDELOAD_HOME, str(state))
    return state


def missing_tool(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    """Make one tool unresolvable; every other tool keeps resolving."""
    original = config.find_tool

    def fake_find(tool: str) -> str | None:
        if tool == name:
            return None
        return original(tool)

    monkeypatch.setattr(config, "find_tool", fake_find)


def write_fake_ipa(path: Path, bundle_id: str = "com.example.nightly") -> Path:
    """A minimal but structurally real IPA: Payload/<app>/Info.plist."""
    import plistlib
    import zipfile

    info = plistlib.dumps({"CFBundleIdentifier": bundle_id})
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("Payload/Nightly.app/Info.plist", info)
        archive.writestr("Payload/Nightly.app/Nightly", b"\xcf\xfa\xed\xfeMachO")
    return path


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


# ------------------------------------------------------------- usbmux tests


def test_list_devices_parses_udids(runner: FakeRunner) -> None:
    runner.script("idevice_id", FakeResult(0, f"{UDID}\n{UDID2}\n\n"))
    transport = usbmux.LibimobiledeviceTransport()
    devices = transport.list_devices()
    assert [device.udid for device in devices] == [UDID, UDID2]
    assert all(isinstance(device, IOSDevice) for device in devices)


def test_list_devices_deduplicates(runner: FakeRunner) -> None:
    runner.script("idevice_id", FakeResult(0, f"{UDID}\n{UDID}\n"))
    transport = usbmux.LibimobiledeviceTransport()
    assert len(transport.list_devices()) == 1


def test_list_devices_missing_tool_names_the_binary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    missing_tool(monkeypatch, config.TOOL_IDEVICE_ID)
    transport = usbmux.LibimobiledeviceTransport()
    with pytest.raises(errors.TransportError) as excinfo:
        transport.list_devices()
    assert config.TOOL_IDEVICE_ID in excinfo.value.message
    assert "brew install libimobiledevice" in str(excinfo.value.hint)


def test_list_devices_tool_failure_raises_device_error(runner: FakeRunner) -> None:
    runner.script("idevice_id", FakeResult(1, "", "usbmuxd is down\n"))
    transport = usbmux.LibimobiledeviceTransport()
    with pytest.raises(errors.DeviceError) as excinfo:
        transport.list_devices()
    assert "usbmuxd is down" in excinfo.value.message


def test_read_device_populates_all_fields(runner: FakeRunner) -> None:
    runner.script(
        "ideviceinfo",
        ideviceinfo_handler(
            {
                (None, "DeviceName"): "Test iPhone",
                (None, "ProductType"): "iPhone12,3",
                (None, "ProductVersion"): "17.6.1",
                (usbmux.DEVELOPER_MODE_DOMAIN, usbmux.DEVELOPER_MODE_KEY): "Enabled",
            }
        ),
    )
    runner.script(
        "idevicepair", FakeResult(0, f"SUCCESS: Validated pairing with device {UDID}\n")
    )
    transport = usbmux.LibimobiledeviceTransport()
    device = transport.read_device(UDID)
    assert device.udid == UDID
    assert device.name == "Test iPhone"
    assert device.product_type == "iPhone12,3"
    assert device.product_version == "17.6.1"
    assert device.paired is True
    assert device.developer_mode_enabled is True


def test_read_device_unpaired_lockdown_refusal(runner: FakeRunner) -> None:
    runner.script("ideviceinfo", ideviceinfo_handler({}))
    runner.script(
        "idevicepair", FakeResult(255, f"ERROR: Device {UDID} is not paired with this host\n")
    )
    transport = usbmux.LibimobiledeviceTransport()
    device = transport.read_device(UDID)
    assert device.name is None
    assert device.paired is False
    assert device.developer_mode_enabled is None


def test_is_paired_yes_and_no(runner: FakeRunner) -> None:
    transport = usbmux.LibimobiledeviceTransport()
    runner.script("idevicepair", FakeResult(0, f"SUCCESS: Validated pairing with device {UDID}\n"))
    assert transport.is_paired(UDID) is True
    runner.script("idevicepair", FakeResult(255, f"ERROR: Device {UDID} is not paired with this host\n"))
    assert transport.is_paired(UDID) is False


def test_is_paired_missing_tool(monkeypatch: pytest.MonkeyPatch) -> None:
    missing_tool(monkeypatch, config.TOOL_IDEVICEPAIR)
    transport = usbmux.LibimobiledeviceTransport()
    with pytest.raises(errors.TransportError) as excinfo:
        transport.is_paired(UDID)
    assert config.TOOL_IDEVICEPAIR in excinfo.value.message


def test_developer_mode_states(runner: FakeRunner) -> None:
    transport = usbmux.LibimobiledeviceTransport()
    key = (usbmux.DEVELOPER_MODE_DOMAIN, usbmux.DEVELOPER_MODE_KEY)
    runner.script("ideviceinfo", ideviceinfo_handler({key: "Enabled"}))
    assert transport.developer_mode_enabled(UDID) is True
    runner.script("ideviceinfo", ideviceinfo_handler({key: "Disabled"}))
    assert transport.developer_mode_enabled(UDID) is False
    # iOS 17 lockdown returns a plist boolean rendered as true/false
    runner.script("ideviceinfo", ideviceinfo_handler({key: "true"}))
    assert transport.developer_mode_enabled(UDID) is True
    runner.script("ideviceinfo", ideviceinfo_handler({key: "false"}))
    assert transport.developer_mode_enabled(UDID) is False
    runner.script("ideviceinfo", ideviceinfo_handler({}))
    assert transport.developer_mode_enabled(UDID) is None


def test_ideviceinfo_missing_tool(monkeypatch: pytest.MonkeyPatch) -> None:
    missing_tool(monkeypatch, config.TOOL_IDEVICEINFO)
    transport = usbmux.LibimobiledeviceTransport()
    with pytest.raises(errors.TransportError) as excinfo:
        transport.read_device(UDID)
    assert config.TOOL_IDEVICEINFO in excinfo.value.message


def test_wait_for_pair_success(runner: FakeRunner) -> None:
    runner.script("idevicepair", FakeResult(0, f"SUCCESS: Paired with device {UDID}\n"))
    transport = usbmux.LibimobiledeviceTransport()
    assert transport.wait_for_pair(UDID, timeout_seconds=5.0) is True
    pair_calls = [call for call in runner.calls if call[1:] == ["-u", UDID, "pair"]]
    assert len(pair_calls) == 1


def test_wait_for_pair_denied_returns_false_immediately(runner: FakeRunner) -> None:
    runner.script(
        "idevicepair",
        FakeResult(255, f"ERROR: Device {UDID} said that the user denied the trust dialog.\n"),
    )
    transport = usbmux.LibimobiledeviceTransport()
    assert transport.wait_for_pair(UDID, timeout_seconds=30.0) is False
    pair_calls = [call for call in runner.calls if call[1:] == ["-u", UDID, "pair"]]
    assert len(pair_calls) == 1


def test_wait_for_pair_timeout_returns_false(runner: FakeRunner) -> None:
    runner.script(
        "idevicepair",
        FakeResult(
            255,
            f"ERROR: Please accept the trust dialog on the screen of device {UDID}, "
            "then attempt to pair again.\n",
        ),
    )
    transport = usbmux.LibimobiledeviceTransport()
    assert transport.wait_for_pair(UDID, timeout_seconds=0.05) is False


def test_wait_for_pair_no_device_raises(runner: FakeRunner) -> None:
    runner.script("idevicepair", FakeResult(255, f"No device found with udid {UDID}.\n"))
    transport = usbmux.LibimobiledeviceTransport()
    with pytest.raises(errors.NoDeviceFoundError):
        transport.wait_for_pair(UDID, timeout_seconds=1.0)


def test_normalize_udid() -> None:
    assert usbmux.normalize_udid("00008101-000000000000000E") == "00008101000000000000000e"
    assert usbmux.normalize_udid(UDID) == usbmux.normalize_udid(UDID2.replace("2E", "1E"))


def test_disk_usage(runner: FakeRunner) -> None:
    runner.script(
        "ideviceinfo",
        ideviceinfo_handler(
            {
                ("com.apple.disk_usage", "TotalDataAvailable"): "127492296704",
                ("com.apple.disk_usage", "TotalDiskCapacity"): "512110190592",
            }
        ),
    )
    transport = usbmux.LibimobiledeviceTransport()
    assert transport.disk_usage(UDID) == (127492296704, 512110190592)


def test_disk_usage_unavailable(runner: FakeRunner) -> None:
    runner.script("ideviceinfo", ideviceinfo_handler({}))
    transport = usbmux.LibimobiledeviceTransport()
    assert transport.disk_usage(UDID) is None


def test_list_device_profiles(runner: FakeRunner) -> None:
    runner.script(
        "ideviceprovision",
        FakeResult(
            0,
            "Device has 1 provisioning profile installed:\n"
            "7A9D29C2-6C63-4E1B-9B3F-9AE7B33B94F3 - "
            "iOS Team Provisioning Profile: com.example.app.TEAMID1\n",
        ),
    )
    transport = usbmux.LibimobiledeviceTransport()
    profiles = transport.list_device_profiles(UDID)
    assert profiles == [
        (
            "7A9D29C2-6C63-4E1B-9B3F-9AE7B33B94F3",
            "iOS Team Provisioning Profile: com.example.app.TEAMID1",
        )
    ]


def test_list_device_profiles_missing_tool(monkeypatch: pytest.MonkeyPatch) -> None:
    missing_tool(monkeypatch, config.TOOL_IDEVICEPROVISION)
    transport = usbmux.LibimobiledeviceTransport()
    with pytest.raises(errors.TransportError) as excinfo:
        transport.list_device_profiles(UDID)
    assert config.TOOL_IDEVICEPROVISION in excinfo.value.message


# ----------------------------------------------------------- installer tests


def make_installer_handler(
    *,
    version: str = "1.2.0",
    apps_stdout: str = "",
    apps_rc: int = 0,
    apps_stderr: str = "",
    install_stdout: str = "",
    install_stderr: str = "",
    install_rc: int = 0,
) -> Callable[[list[str]], FakeResult]:
    """Script ideviceinstaller: version probe, list, install, uninstall."""

    def handle(cmd: list[str]) -> FakeResult:
        if "--version" in cmd:
            return FakeResult(0, f"ideviceinstaller {version}\n")
        if "list" in cmd or "list_user" in cmd or "list_all" in cmd or "-l" in cmd:
            return FakeResult(apps_rc, apps_stdout, apps_stderr)
        if "uninstall" in cmd or "-U" in cmd:
            if install_rc == 0:
                return FakeResult(0, f"Uninstalling '{cmd[-1]}'\n\rUninstall: Complete\n")
            return FakeResult(install_rc, "", install_stderr)
        return FakeResult(install_rc, install_stdout, install_stderr)

    return handle


def test_list_apps_modern_format(runner: FakeRunner) -> None:
    runner.script(
        "ideviceinstaller",
        make_installer_handler(
            apps_stdout=(
                "CFBundleIdentifier, CFBundleShortVersionString, CFBundleDisplayName\n"
                "com.example.app, 1.2.3, Example App\n"
                "com.example.two, , Two\n"
            )
        ),
    )
    client = installer.DeviceAppClient(usbmux.LibimobiledeviceTransport())
    apps = client.list_apps(UDID, user_apps_only=True)
    assert apps[0].bundle_identifier == "com.example.app"
    assert apps[0].name == "Example App"
    assert apps[0].version == "1.2.3"
    assert apps[1].bundle_identifier == "com.example.two"
    assert apps[1].name == "Two"
    assert apps[1].version is None
    list_call = next(call for call in runner.calls if "list" in call)
    assert list_call[1:] == ["-u", UDID, "list", "--user"]


def test_list_apps_modern_all_flag(runner: FakeRunner) -> None:
    runner.script("ideviceinstaller", make_installer_handler(apps_stdout=""))
    client = installer.DeviceAppClient(usbmux.LibimobiledeviceTransport())
    assert client.list_apps(UDID, user_apps_only=False) == []
    list_call = next(call for call in runner.calls if "list" in call)
    assert list_call[1:] == ["-u", UDID, "list", "--all"]


def test_list_apps_legacy_format(runner: FakeRunner) -> None:
    runner.script(
        "ideviceinstaller",
        make_installer_handler(
            version="1.1.0",
            apps_stdout=(
                "Total: 3 apps\n"
                "com.example.app - Example App 1.2.3\n"
                "com.example.two - TwoApp\n"
                "com.example.three - My Cool App 2.0\n"
            ),
        ),
    )
    client = installer.DeviceAppClient(usbmux.LibimobiledeviceTransport())
    apps = client.list_apps(UDID)
    assert apps[0].bundle_identifier == "com.example.app"
    assert apps[0].name == "Example App"
    assert apps[0].version == "1.2.3"
    # "id - Name version" rows are ambiguous; the last token is the version
    assert apps[1].bundle_identifier == "com.example.two"
    assert apps[1].name == "TwoApp"
    assert apps[1].version is None
    assert apps[2].name == "My Cool App"
    assert apps[2].version == "2.0"
    list_call = next(call for call in runner.calls if "-l" in call)
    assert list_call[1:] == ["-u", UDID, "-l", "-o", "list_user"]


def test_list_apps_missing_installer_names_the_tool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    missing_tool(monkeypatch, config.TOOL_IDEVICEINSTALLER)
    client = installer.DeviceAppClient(usbmux.LibimobiledeviceTransport())
    with pytest.raises(errors.TransportError) as excinfo:
        client.list_apps(UDID)
    assert config.TOOL_IDEVICEINSTALLER in excinfo.value.message
    assert "brew install ideviceinstaller" in str(excinfo.value.hint)


def test_list_apps_unpaired_maps_to_pairing_error(runner: FakeRunner) -> None:
    runner.script(
        "ideviceinstaller",
        make_installer_handler(
            apps_rc=255, apps_stdout="", apps_stderr="Could not connect to lockdownd. Exiting.\n"
        ),
    )
    client = installer.DeviceAppClient(usbmux.LibimobiledeviceTransport())
    with pytest.raises(errors.PairingError):
        client.list_apps(UDID)


def test_list_apps_no_device_maps_to_no_device_found(runner: FakeRunner) -> None:
    runner.script(
        "ideviceinstaller",
        make_installer_handler(
            apps_rc=1, apps_stdout="", apps_stderr="No device found.\n"
        ),
    )
    client = installer.DeviceAppClient(usbmux.LibimobiledeviceTransport())
    with pytest.raises(errors.NoDeviceFoundError):
        client.list_apps(UDID)


def test_install_replays_stages_and_uses_upgrade_when_installed(
    runner: FakeRunner, tmp_path: Path
) -> None:
    ipa = write_fake_ipa(tmp_path / "nightly.ipa", bundle_id="com.example.nightly.teamid1")
    runner.script(
        "ideviceinstaller",
        make_installer_handler(
            apps_stdout="CFBundleIdentifier, CFBundleShortVersionString, CFBundleDisplayName\n"
            "com.example.nightly.teamid1, 1.0, Nightly\n",
            install_stdout=(
                "Copying 'nightly.ipa' to device... DONE.\n"
                "Upgrading 'com.example.nightly.teamid1'\n"
                "\rUpgrade: CreatingStagingDirectory (10%)"
                "\r\rUpgrade: ExtractingPackage (50%)"
                "\r\rUpgrade: VerifyingApplication"
                "\r\rUpgrade: Complete\n"
            ),
        ),
    )
    client = installer.DeviceAppClient(usbmux.LibimobiledeviceTransport())
    stages: list[tuple[str, int | None]] = []
    client.install(UDID, str(ipa), progress=lambda stage, percent: stages.append((stage, percent)))
    assert stages == [
        ("CreatingStagingDirectory", 10),
        ("ExtractingPackage", 50),
        ("VerifyingApplication", None),
        ("Complete", None),
    ]
    install_call = next(
        call for call in runner.calls if "upgrade" in call or "install" in call
    )
    assert install_call[1:] == ["-u", UDID, "upgrade", str(ipa)]


def test_install_uses_install_command_for_new_bundle(
    runner: FakeRunner, tmp_path: Path
) -> None:
    ipa = write_fake_ipa(tmp_path / "fresh.ipa")
    runner.script("ideviceinstaller", make_installer_handler(apps_stdout=""))
    client = installer.DeviceAppClient(usbmux.LibimobiledeviceTransport())
    client.install(UDID, str(ipa), progress=None)
    install_call = next(
        call for call in runner.calls if call[-1] == str(ipa) and "list" not in call
    )
    assert install_call[1:] == ["-u", UDID, "install", str(ipa)]


def test_install_progress_callback_optional(runner: FakeRunner, tmp_path: Path) -> None:
    ipa = write_fake_ipa(tmp_path / "plain.ipa")
    runner.script(
        "ideviceinstaller",
        make_installer_handler(install_stdout="\rInstall: Complete\n"),
    )
    client = installer.DeviceAppClient(usbmux.LibimobiledeviceTransport())
    client.install(UDID, str(ipa), progress=None)


def test_install_missing_ipa_file(runner: FakeRunner, tmp_path: Path) -> None:
    client = installer.DeviceAppClient(usbmux.LibimobiledeviceTransport())
    with pytest.raises(errors.InstallError) as excinfo:
        client.install(UDID, str(tmp_path / "nope.ipa"), progress=None)
    assert "not found" in excinfo.value.message


def test_install_maps_application_verification_failed(
    runner: FakeRunner, tmp_path: Path
) -> None:
    ipa = write_fake_ipa(tmp_path / "nightly.ipa", bundle_id="com.example.nightly.teamid1")
    runner.script(
        "ideviceinstaller",
        make_installer_handler(
            apps_stdout="com.example.nightly.teamid1, 1.0, Nightly\n",
            install_rc=255,
            install_stderr=(
                'ERROR: Upgrade failed. Got error "ApplicationVerificationFailed" '
                "with code 0xe8008001: Failed to get code directory\n"
            ),
        ),
    )
    client = installer.DeviceAppClient(usbmux.LibimobiledeviceTransport())
    with pytest.raises(errors.InstallError) as excinfo:
        client.install(UDID, str(ipa), progress=None)
    assert excinfo.value.install_error_name == "ApplicationVerificationFailed"
    assert excinfo.value.error_description == "Failed to get code directory"
    assert excinfo.value.message == (
        "Upgrade failed: ApplicationVerificationFailed: Failed to get code directory"
    )
    assert "sideload doctor" in str(excinfo.value.hint)


def test_install_maps_mismatched_application_identifier(
    runner: FakeRunner, tmp_path: Path
) -> None:
    ipa = write_fake_ipa(tmp_path / "nightly.ipa")
    runner.script(
        "ideviceinstaller",
        make_installer_handler(
            install_rc=255,
            install_stderr=(
                'ERROR: Install failed. Got error "MismatchedApplicationIdentifierEntitlement".\n'
            ),
        ),
    )
    client = installer.DeviceAppClient(usbmux.LibimobiledeviceTransport())
    with pytest.raises(errors.InstallError) as excinfo:
        client.install(UDID, str(ipa), progress=None)
    assert excinfo.value.install_error_name == "MismatchedApplicationIdentifierEntitlement"
    assert "Uninstall it first" in str(excinfo.value.hint)


def test_install_legacy_error_line(runner: FakeRunner, tmp_path: Path) -> None:
    ipa = write_fake_ipa(tmp_path / "nightly.ipa")
    runner.script(
        "ideviceinstaller",
        make_installer_handler(
            version="1.1.0",
            install_rc=255,
            install_stdout="Install - Error occurred: PackageExtractionFailed\n",
        ),
    )
    client = installer.DeviceAppClient(usbmux.LibimobiledeviceTransport())
    with pytest.raises(errors.InstallError) as excinfo:
        client.install(UDID, str(ipa), progress=None)
    assert excinfo.value.install_error_name == "PackageExtractionFailed"
    assert "extracted" in str(excinfo.value.hint)


def test_install_no_device(runner: FakeRunner, tmp_path: Path) -> None:
    ipa = write_fake_ipa(tmp_path / "nightly.ipa")
    runner.script(
        "ideviceinstaller",
        make_installer_handler(install_rc=1, install_stderr="No device found.\n"),
    )
    client = installer.DeviceAppClient(usbmux.LibimobiledeviceTransport())
    with pytest.raises(errors.NoDeviceFoundError):
        client.install(UDID, str(ipa), progress=None)


def test_uninstall_requires_confirmation(runner: FakeRunner) -> None:
    runner.script("ideviceinstaller", make_installer_handler())
    client = installer.DeviceAppClient(usbmux.LibimobiledeviceTransport())
    with pytest.raises(errors.UninstallConfirmationRequired):
        client.uninstall(UDID, "com.example.app", confirmed=False)
    assert runner.calls == []  # no tool was contacted


def test_uninstall_success_modern(runner: FakeRunner) -> None:
    runner.script("ideviceinstaller", make_installer_handler())
    client = installer.DeviceAppClient(usbmux.LibimobiledeviceTransport())
    client.uninstall(UDID, "com.example.app", confirmed=True)
    uninstall_call = next(call for call in runner.calls if "uninstall" in call)
    assert uninstall_call[1:] == ["-u", UDID, "uninstall", "com.example.app"]


def test_uninstall_success_legacy(runner: FakeRunner) -> None:
    runner.script("ideviceinstaller", make_installer_handler(version="1.1.0"))
    client = installer.DeviceAppClient(usbmux.LibimobiledeviceTransport())
    client.uninstall(UDID, "com.example.app", confirmed=True)
    uninstall_call = next(call for call in runner.calls if "-U" in call)
    assert uninstall_call[1:] == ["-u", UDID, "-U", "com.example.app"]


def test_uninstall_failure_maps_install_error(runner: FakeRunner) -> None:
    runner.script(
        "ideviceinstaller",
        make_installer_handler(
            install_rc=255,
            install_stderr='ERROR: Uninstall failed. Got error "UnknownError".\n',
        ),
    )
    client = installer.DeviceAppClient(usbmux.LibimobiledeviceTransport())
    with pytest.raises(errors.InstallError) as excinfo:
        client.uninstall(UDID, "com.example.app", confirmed=True)
    assert excinfo.value.install_error_name == "UnknownError"


def test_diagnose_full_report(runner: FakeRunner) -> None:
    runner.script(
        "ideviceinfo",
        ideviceinfo_handler(
            {
                (usbmux.DEVELOPER_MODE_DOMAIN, usbmux.DEVELOPER_MODE_KEY): "Enabled",
                ("com.apple.disk_usage", "TotalDataAvailable"): "127492296704",
                ("com.apple.disk_usage", "TotalDiskCapacity"): "512110190592",
            }
        ),
    )
    runner.script("idevicepair", FakeResult(0, f"SUCCESS: Validated pairing with device {UDID}\n"))
    runner.script("ideviceprovision", FakeResult(0, "Device has 0 provisioning profiles installed:\n"))
    runner.script("ideviceinstaller", make_installer_handler(apps_stdout=""))
    client = installer.DeviceAppClient(usbmux.LibimobiledeviceTransport())
    lines = client.diagnose(UDID, follow_logs=False)
    joined = "\n".join(lines)
    assert "pairing: yes" in joined
    assert "developer mode: on" in joined
    assert "free disk space: 127.5 GB of 512.1 GB" in joined
    assert "device provisioning profiles: 0" in joined
    assert "installed user apps: 0" in joined


def test_diagnose_developer_mode_off_hint(runner: FakeRunner) -> None:
    runner.script(
        "ideviceinfo",
        ideviceinfo_handler(
            {(usbmux.DEVELOPER_MODE_DOMAIN, usbmux.DEVELOPER_MODE_KEY): "Disabled"}
        ),
    )
    runner.script("idevicepair", FakeResult(255, f"ERROR: Device {UDID} is not paired with this host\n"))
    runner.script("ideviceinstaller", make_installer_handler(apps_stdout=""))
    client = installer.DeviceAppClient(usbmux.LibimobiledeviceTransport())
    lines = client.diagnose(UDID, follow_logs=False)
    joined = "\n".join(lines)
    assert "developer mode: off" in joined
    assert "Settings > Privacy and Security > Developer Mode" in joined
    assert "pairing: no" in joined


def test_diagnose_missing_installer_degrades(
    runner: FakeRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    missing_tool(monkeypatch, config.TOOL_IDEVICEINSTALLER)
    runner.script("ideviceinfo", ideviceinfo_handler({}))
    runner.script("idevicepair", FakeResult(0, f"SUCCESS: Validated pairing with device {UDID}\n"))
    client = installer.DeviceAppClient(usbmux.LibimobiledeviceTransport())
    lines = client.diagnose(UDID, follow_logs=False)
    joined = "\n".join(lines)
    assert "pairing: yes" in joined
    assert "installed apps: unavailable (required tool 'ideviceinstaller' is not installed)" in joined
    assert "device provisioning profiles: 0" in joined


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


def test_follow_logs_filters_lines(
    runner: FakeRunner, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    canned = [
        "installd: MobileInstallationRunLoop: installing\n",
        "springboard: unrelated\n",
        "amfid: code signature invalid\n",
        "AppleMobileFileIntegrity: entitlements rejected\n",
        "installd: \x1b[31mred\x1b[0m stage\n",
        "kernel: noise\n",
    ]
    monkeypatch.setattr(
        installer, "_popen_subprocess", lambda cmd: FakePopen(canned)
    )
    client = installer.DeviceAppClient(usbmux.LibimobiledeviceTransport())
    client.follow_logs(UDID)
    out = capsys.readouterr().out
    assert "installd: MobileInstallationRunLoop" in out
    assert "amfid: code signature invalid" in out
    assert "AppleMobileFileIntegrity: entitlements rejected" in out
    assert "unrelated" not in out
    assert "kernel: noise" not in out
    assert "\x1b" not in out
    assert "installd: red stage" in out


def test_follow_logs_missing_tool(
    runner: FakeRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    missing_tool(monkeypatch, config.TOOL_IDEVICESYSLOG)
    client = installer.DeviceAppClient(usbmux.LibimobiledeviceTransport())
    with pytest.raises(errors.TransportError) as excinfo:
        client.follow_logs(UDID)
    assert config.TOOL_IDEVICESYSLOG in excinfo.value.message


def test_diagnose_follow_logs_prints_report_then_streams(
    runner: FakeRunner, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    runner.script("ideviceinfo", ideviceinfo_handler({}))
    runner.script("idevicepair", FakeResult(0, f"SUCCESS: Validated pairing with device {UDID}\n"))
    runner.script("ideviceinstaller", make_installer_handler(apps_stdout=""))
    monkeypatch.setattr(
        installer, "_popen_subprocess", lambda cmd: FakePopen(["installd: done\n"])
    )
    client = installer.DeviceAppClient(usbmux.LibimobiledeviceTransport())
    lines = client.diagnose(UDID, follow_logs=True)
    out = capsys.readouterr().out
    assert "pairing: yes" in out
    assert "installd: done" in out
    assert lines[0].startswith("pairing:")


def test_bundle_id_of_ipa_reads_payload_info_plist(tmp_path: Path) -> None:
    import plistlib
    import zipfile

    ipa = tmp_path / "app.ipa"
    info = plistlib.dumps({"CFBundleIdentifier": "com.example.nightly"})
    with zipfile.ZipFile(ipa, "w") as archive:
        archive.writestr("Payload/Nightly.app/Info.plist", info)
        archive.writestr("Payload/Nightly.app/Nightly", b"MachO")
    assert installer._bundle_id_of_ipa(str(ipa)) == "com.example.nightly"
    assert installer._bundle_id_of_ipa(str(tmp_path / "missing.ipa")) is None


def test_install_error_hint_for_free_app_limit() -> None:
    client = installer.DeviceAppClient(usbmux.LibimobiledeviceTransport())
    error = client._install_error_from(
        "ApplicationVerificationFailed",
        "The maximum number of apps for free development profiles has been reached.",
        "Install",
    )
    assert error.hint is not None
    assert "three sideloaded apps" in error.hint


def test_uninstall_without_confirmation_uses_usage_exit_code() -> None:
    error = errors.UninstallConfirmationRequired("confirm first")
    assert error.exit_code == 2


def test_install_error_hint_uses_the_error_code() -> None:
    client = installer.DeviceAppClient(usbmux.LibimobiledeviceTransport())
    error = client._install_error_from(
        "ApplicationVerificationFailed", "generic failure", "Install", "0xe8008021"
    )
    assert error.hint is not None
    assert "three sideloaded apps" in error.hint


def test_is_paired_locked_device_raises_with_unlock_hint(runner: FakeRunner) -> None:
    transport = usbmux.LibimobiledeviceTransport()
    runner.script(
        "idevicepair",
        FakeResult(255, "Could not validate with device because a passcode is set.\n"),
    )
    with pytest.raises(errors.PairingError) as excinfo:
        transport.is_paired(UDID)
    assert "unlock" in (excinfo.value.hint or "")
