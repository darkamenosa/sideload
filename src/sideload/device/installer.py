"""App install, uninstall, and listing through installation_proxy.

Install mechanics (see DESIGN.md "Install mechanics"):

    ideviceinstaller is the subprocess front end to Apple's
    com.apple.mobile.installation_proxy service. It stages the IPA over
    AFC into Public/Staging and then issues the Upgrade command with
    CFBundleIdentifier and CFBundleShortVersionString options. The same
    protocol is what AltStore drives directly.

    The proxy streams progress plists with keys Status ("Complete",
    or a stage name like "CreatingStagingDirectory",
    "ExtractingPackage", "VerifyingApplication"), PercentComplete, and,
    on failure, Error plus ErrorDescription. ideviceinstaller prints
    failures to stderr as:
        ERROR: Upgrade failed. Got error "<Error>" with code 0x...: <ErrorDescription>
    which this module parses; the structured error name maps to hints
    via errors.INSTALL_ERROR_HINTS.

    When the proxy error is not actionable, the real verification
    reason is usually in the device syslog (installd, amfid,
    AppleMobileFileIntegrity lines); "sideload doctor --follow-logs"
    streams and filters those lines with idevicesyslog.

Uninstall is destructive: it removes the app and its data. The CLI
refuses to run it unless --yes is passed and never prompts on its own.

Ownership: DEVICE agent.
"""

from __future__ import annotations

import os
import plistlib
import re
import subprocess
import zipfile
from collections.abc import Callable, Sequence

from sideload import config
from sideload.device.usbmux import LibimobiledeviceTransport
from sideload.errors import (
    INSTALL_ERROR_HINTS,
    DeviceError,
    InstallError,
    NoDeviceFoundError,
    PairingError,
    TransportError,
    UninstallConfirmationRequired,
)
from sideload.models import InstalledApp

# installation_proxy progress stage names worth showing the user.
STAGE_CREATING_STAGING = "CreatingStagingDirectory"
STAGE_EXTRACTING = "ExtractingPackage"
STAGE_VERIFYING = "VerifyingApplication"
STAGE_COMPLETE = "Complete"

TOOL_HINT = "brew install ideviceinstaller"

# ideviceinstaller 1.2.0 or newer, on stderr. Both variants verified in
# the tool source (status_cb):
#   with description:    ERROR: Install failed. Got error "Name" with code 0x...: Description
#   without description: ERROR: Install failed. Got error "Name".
_ERROR_LINE = re.compile(
    r'^ERROR: (?P<command>\w+) failed\. Got error "(?P<name>[^"]+)"'
    r"(?: with code (?P<code>0x[0-9a-fA-F]+))?(?:: (?P<description>.*))?\.?$"
)
# ideviceinstaller 1.1.x: "Install - Error occurred: Name" on stdout.
_LEGACY_ERROR_LINE = re.compile(
    r"^(?P<command>Install|Upgrade|Uninstall) - Error occurred: (?P<name>.+?)\s*$"
)
# Both flavors: "Install: CreatingStagingDirectory (10%)" or
# "Install - ExtractingPackage (25%)".
_STAGE_LINE = re.compile(
    r"^(?:Install|Upgrade|Uninstall)(?::| -) (?P<stage>\w+)(?: \((?P<percent>\d+)%\))?$"
)

# Device syslog is attacker controlled; strip ANSI escapes before printing.
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")

# Read only timeouts: installs and uninstalls run without one because a
# big IPA legitimately takes minutes to stage.
LIST_TIMEOUT_SECONDS = 120.0


def _run_subprocess(
    cmd: Sequence[str], timeout: float | None = None
) -> subprocess.CompletedProcess[str]:
    """Run one external tool. Module level so tests can script tool
    output without ever contacting a real device.
    """
    return subprocess.run(
        list(cmd),
        capture_output=True,
        check=False,
        text=True,
        errors="replace",
        timeout=timeout,
    )


def _popen_subprocess(cmd: Sequence[str]) -> subprocess.Popen[str]:
    """Start a streaming tool (idevicesyslog). Module level for tests."""
    return subprocess.Popen(
        list(cmd),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        errors="replace",
    )


def _bundle_id_of_ipa(ipa_path: str) -> str | None:
    """CFBundleIdentifier of the main .app inside the IPA, read locally
    from the zip. Used to choose the proxy Upgrade command over Install
    when the bundle is already on the device.
    """
    try:
        with zipfile.ZipFile(ipa_path) as archive:
            for name in archive.namelist():
                parts = name.split("/")
                if (
                    len(parts) == 3
                    and parts[0] == "Payload"
                    and parts[1].endswith(".app")
                    and parts[2] == "Info.plist"
                ):
                    info = plistlib.loads(archive.read(name))
                    bundle_id = info.get("CFBundleIdentifier")
                    return bundle_id if isinstance(bundle_id, str) else None
    except (OSError, ValueError, zipfile.BadZipFile, plistlib.InvalidFileException):
        return None
    return None


def _parse_app_lines(stdout: str) -> list[InstalledApp]:
    """Parse "ideviceinstaller list" output rows.

    1.2.x prints "CFBundleIdentifier, CFBundleShortVersionString,
    CFBundleDisplayName" rows ("id, 1.2.3, Name"); 1.1.x prints a
    "Total: N apps" header then "id - Name 1.2.3" rows. Both are
    handled; quotes and blank fields are tolerated.
    """
    apps: list[InstalledApp] = []
    for line in stdout.splitlines():
        line = line.strip().strip("\r").strip()
        if not line or line.startswith(("Total:", "CFBundleIdentifier")):
            continue
        if line.startswith(("NOTE:", "WARNING:", "ERROR:")):
            continue
        app = _parse_app_line(line)
        if app is not None:
            apps.append(app)
    return apps


def _parse_app_line(line: str) -> InstalledApp | None:
    if ", " in line:
        parts = [part.strip().strip('"') for part in line.split(", ", 2)]
        bundle_id = parts[0]
        version = parts[1] if len(parts) > 1 else ""
        name = parts[2] if len(parts) > 2 else ""
        if not bundle_id or " " in bundle_id:
            return None
        return InstalledApp(
            bundle_identifier=bundle_id,
            name=name or None,
            version=version or None,
        )
    if " - " in line:
        bundle_id, _, rest = line.partition(" - ")
        bundle_id = bundle_id.strip().strip('"')
        rest = rest.strip().strip('"')
        if not bundle_id or " " in bundle_id:
            return None
        if " " in rest:
            name, _, version = rest.rpartition(" ")
        else:
            name, version = rest, ""
        return InstalledApp(
            bundle_identifier=bundle_id,
            name=name or None,
            version=version or None,
        )
    return None


def _parse_progress(stdout: str) -> list[tuple[str, int | None]]:
    """Stage/percent pairs from ideviceinstaller progress output.

    ideviceinstaller paints progress with carriage returns, so the
    captured stdout is split on both newline and carriage return.
    """
    stages: list[tuple[str, int | None]] = []
    for chunk in re.split(r"[\r\n]+", stdout):
        chunk = chunk.strip()
        if not chunk:
            continue
        match = _STAGE_LINE.match(chunk)
        if match is None:
            continue
        percent_raw = match.group("percent")
        percent = int(percent_raw) if percent_raw is not None else None
        stages.append((match.group("stage"), percent))
    return stages


class DeviceAppClient:
    """Install, list, and uninstall apps on one paired device."""

    def __init__(self, transport: LibimobiledeviceTransport) -> None:
        """Bind to a transport; no device is contacted yet."""
        self.transport = transport
        # ideviceinstaller invocation flavor: 1.2.0 uses subcommands
        # ("list --user", "install", "uninstall"); 1.1.x uses flags
        # ("-l -o list_user", "-i", "-U"). DESIGN.md pins 1.2.0, so the
        # modern form is the default; the legacy form is kept working
        # because the pinned interface docstrings describe it.
        self._flavor: str | None = None

    # ------------------------------------------------------------ plumbing

    def _tool_path(self) -> str:
        """Resolve ideviceinstaller or raise with the brew hint."""
        path = config.find_tool(config.TOOL_IDEVICEINSTALLER)
        if path is None:
            raise TransportError(
                "required tool 'ideviceinstaller' is not installed",
                hint=TOOL_HINT,
            )
        return path

    def _detect_flavor(self) -> str:
        if self._flavor is not None:
            return self._flavor
        flavor = "modern"
        try:
            proc = _run_subprocess([self._tool_path(), "--version"], timeout=15.0)
            match = re.search(r"(?P<major>\d+)\.(?P<minor>\d+)", proc.stdout)
            if match is not None and (int(match.group("major")), int(match.group("minor"))) < (1, 2):
                flavor = "legacy"
        except TransportError:
            raise
        except (OSError, subprocess.SubprocessError):
            flavor = "modern"
        self._flavor = flavor
        return flavor

    def _run(
        self, args: Sequence[str], timeout: float | None = None
    ) -> subprocess.CompletedProcess[str]:
        return _run_subprocess([self._tool_path(), *[str(arg) for arg in args]], timeout=timeout)

    def _raise_connection_error(
        self, proc: subprocess.CompletedProcess[str], operation: str
    ) -> None:
        """Map ideviceinstaller connection failures onto the taxonomy."""
        detail = f"{proc.stdout}\n{proc.stderr}".strip()
        lowered = detail.lower()
        if "no device found" in lowered or "no ios device found" in lowered:
            raise NoDeviceFoundError(
                "ideviceinstaller could not find the device",
                hint="plug the device in over USB and unlock it",
            )
        if "lockdownd" in lowered or "pair" in lowered:
            raise PairingError(
                "the device is not paired with this Mac",
                hint='run "sideload devices --pair" and accept the trust dialog on the iPhone',
            )
        message = f"{operation} failed"
        if detail:
            message = f"{message}: {detail.splitlines()[0]}"
        else:
            message = f"{message}: ideviceinstaller exited with code {proc.returncode}"
        raise InstallError(message)

    def _find_install_error(
        self, proc: subprocess.CompletedProcess[str], operation: str
    ) -> InstallError | None:
        """Parse the structured installation_proxy error line."""
        combined = f"{proc.stdout}\n{proc.stderr}"
        for line in combined.splitlines():
            line = line.strip()
            match = _ERROR_LINE.match(line)
            if match is not None:
                return self._install_error_from(
                    match.group("name"),
                    match.group("description"),
                    operation,
                    match.group("code"),
                )
            match = _LEGACY_ERROR_LINE.match(line)
            if match is not None:
                return self._install_error_from(
                    match.group("name").strip(),
                    None,
                    operation,
                )
        return None

    def _install_error_from(
        self,
        error_name: str,
        description: str | None,
        operation: str,
        code: str | None = None,
    ) -> InstallError:
        hint = INSTALL_ERROR_HINTS.get(error_name, INSTALL_ERROR_HINTS["UnknownError"])
        lowered = (description or "").lower()
        if (code or "").lower() == "0xe8008021" or "maximum number of apps" in lowered:
            hint = (
                "Free Apple accounts can have three sideloaded apps at a time. "
                "Uninstall one with: sideload uninstall <bundle-id> --yes, "
                "or use a paid team."
            )
        message = f"{operation} failed: {error_name}"
        if description:
            message = f"{message}: {description}"
        return InstallError(
            message,
            install_error_name=error_name,
            error_description=description,
            hint=hint,
        )

    # ------------------------------------------------------------- listing

    def list_apps(self, udid: str, user_apps_only: bool = True) -> list[InstalledApp]:
        """ideviceinstaller -u <udid> -l; one row per installed app.

        Raises PairingError when the device is not paired.
        """
        selector = "list_user" if user_apps_only else "list_all"
        if self._detect_flavor() == "legacy":
            args: list[str] = ["-u", udid, "-l", "-o", selector]
        else:
            args = ["-u", udid, "list", "--user" if user_apps_only else "--all"]
        proc = self._run(args, timeout=LIST_TIMEOUT_SECONDS)
        if proc.returncode != 0:
            self._raise_connection_error(proc, "listing apps")
        return _parse_app_lines(proc.stdout)

    # ------------------------------------------------------------- install

    def install(
        self,
        udid: str,
        ipa_path: str,
        progress: Callable[[str, int | None], None] | None = None,
        bundle_id: str | None = None,
    ) -> None:
        """Install (upgrade) one IPA on the device.

        Runs ideviceinstaller -u <udid> -i <ipa>, streaming stage and
        percentage to progress(stage, percent). On failure parses the
        stderr error line and raises InstallError with the structured
        name and description, with the hint from
        errors.INSTALL_ERROR_HINTS attached.

        Known failure names mapped here:
            ApplicationVerificationFailed, BundleVerificationFailed,
            MismatchedApplicationIdentifierEntitlement,
            PackageExtractionFailed, InsufficientDiskSpace,
            EmbeddedProfileInstallFailed, NotEntitled,
            InstallProhibited.

        Implementation note: the tool paints progress with carriage
        returns on stdout, so the completed output is parsed and every
        stage is replayed to the progress callback in order.
        """
        if not os.path.isfile(ipa_path):
            raise InstallError(f"install failed: IPA file not found: {ipa_path}")

        # Best effort pre-list: when the bundle id is already installed
        # the proxy Upgrade command replaces it (AltStore semantics).
        installed_ids: set[str] | None = None
        try:
            installed_ids = {
                app.bundle_identifier for app in self.list_apps(udid, user_apps_only=False)
            }
        except (TransportError, NoDeviceFoundError, PairingError, InstallError):
            installed_ids = None
        target_bundle_id = bundle_id or _bundle_id_of_ipa(ipa_path)
        use_upgrade = bool(
            target_bundle_id and installed_ids and target_bundle_id in installed_ids
        )

        if self._detect_flavor() == "legacy":
            args = ["-u", udid, "-g" if use_upgrade else "-i", ipa_path]
        else:
            args = ["-u", udid, "upgrade" if use_upgrade else "install", ipa_path]

        proc = self._run(args)
        error = self._find_install_error(proc, "Upgrade" if use_upgrade else "Install")
        if error is not None:
            raise error
        if proc.returncode != 0:
            self._raise_connection_error(proc, "install")
        if progress is not None:
            for stage, percent in _parse_progress(proc.stdout):
                progress(stage, percent)

    # ----------------------------------------------------------- uninstall

    def uninstall(self, udid: str, bundle_id: str, confirmed: bool) -> None:
        """Uninstall one app. Requires confirmed=True (the CLI passes
        the --yes flag through). Raises UninstallConfirmationRequired
        otherwise, and never asks the user itself.
        """
        if not confirmed:
            raise UninstallConfirmationRequired(
                "uninstall removes the app and its data; --yes is required",
                hint="re-run: sideload uninstall <bundle-id> --yes",
            )
        if self._detect_flavor() == "legacy":
            args: list[str] = ["-u", udid, "-U", bundle_id]
        else:
            args = ["-u", udid, "uninstall", bundle_id]
        proc = self._run(args)
        error = self._find_install_error(proc, "Uninstall")
        if error is not None:
            raise error
        if proc.returncode != 0:
            self._raise_connection_error(proc, "uninstall")

    # ----------------------------------------------------------- diagnose

    def diagnose(
        self,
        udid: str,
        follow_logs: bool = False,
    ) -> list[str]:
        """Human readable health report for one device: pairing
        status, developer mode status, free disk space, and whether the
        currently installed apps include ones signed by this tool.

        With follow_logs, streams filtered installd/amfid syslog lines
        (idevicesyslog) until interrupted; used to find the real cause
        behind ApplicationVerificationFailed.

        Implementation notes: every probe degrades into a report line
        instead of raising, so one missing tool (for example
        ideviceinstaller before "brew install ideviceinstaller") never
        hides the rest of the report. The "signed by this tool" count
        lives in the install record cache, which this class cannot
        reach through the pinned constructor; the CLI prints it after
        these lines (see cmd_doctor). With follow_logs the report lines
        are printed here before the stream starts.
        """
        lines: list[str] = []

        def probe(label: str, action: Callable[[], list[str]]) -> None:
            """Run one diagnostic; any failure becomes a report line so a
            single missing tool never hides the rest of the report.
            """
            try:
                lines.extend(action())
            except (DeviceError, InstallError) as exc:
                # TransportError is a DeviceError, so missing tools land
                # here too and become a report line instead of an abort.
                lines.append(f"{label}: unavailable ({exc.message})")

        def pairing_lines() -> list[str]:
            paired = self.transport.is_paired(udid)
            result = [f"pairing: {'yes' if paired else 'no'}"]
            if not paired:
                result.append('  hint: run "sideload devices --pair" and accept the trust dialog')
            return result

        def mode_lines() -> list[str]:
            mode = self.transport.developer_mode_enabled(udid)
            if mode is None:
                return ["developer mode: unknown"]
            if mode:
                return ["developer mode: on"]
            return [
                "developer mode: off",
                "  enable it on the device: Settings > Privacy and Security > Developer Mode",
            ]

        def disk_lines() -> list[str]:
            usage = self.transport.disk_usage(udid)
            if usage is None:
                return ["free disk space: unknown"]
            free, total = usage
            return [f"free disk space: {free / 1e9:.1f} GB of {total / 1e9:.1f} GB"]

        def profile_lines() -> list[str]:
            profiles = self.transport.list_device_profiles(udid)
            return [f"device provisioning profiles: {len(profiles)}"]

        def app_lines() -> list[str]:
            apps = self.list_apps(udid)
            return [f"installed user apps: {len(apps)}"]

        probe("pairing", pairing_lines)
        probe("developer mode", mode_lines)
        probe("free disk space", disk_lines)
        probe("device provisioning profiles", profile_lines)
        probe("installed apps", app_lines)

        if follow_logs:
            for line in lines:
                print(line)
            self.follow_logs(udid)
        return lines

    # -------------------------------------------------------- log streaming

    def follow_logs(self, udid: str) -> None:
        """Stream idevicesyslog lines filtered to installd, amfid, and
        AppleMobileFileIntegrity until the stream ends or the user
        presses Ctrl-C (GLUE addition used by "doctor --follow-logs").
        """
        tool = config.find_tool(config.TOOL_IDEVICESYSLOG)
        if tool is None:
            raise TransportError(
                "required tool 'idevicesyslog' is not installed",
                hint="brew install libimobiledevice",
            )
        print(
            "streaming device syslog filtered to installd, amfid, and "
            "AppleMobileFileIntegrity; press Ctrl-C to stop"
        )
        process = _popen_subprocess([tool, "-u", udid])
        try:
            if process.stdout is not None:
                for raw in process.stdout:
                    line = _ANSI_ESCAPE.sub("", raw.rstrip("\r\n"))
                    if any(tag in line for tag in ("installd", "amfid", "AppleMobileFileIntegrity")):
                        print(line)
        except KeyboardInterrupt:
            # Ctrl-C is the documented way to end the stream.
            pass
        finally:
            process.terminate()
            try:
                process.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                process.kill()
