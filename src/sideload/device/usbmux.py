"""USB device discovery and lockdown state via libimobiledevice.

Design choice (see DESIGN.md "Install mechanics" for the full trade
study): the device layer drives the installed libimobiledevice tools
(idevice_id, ideviceinfo, idevicepair, all LGPL-2.1) as subprocesses
instead of implementing the usbmux/lockdown protocol in Python. The
tools are already present on this host (verified: idevice_id,
ideviceinfo, idevicepair, ideviceprovision, iproxy; ideviceinstaller
must be installed separately with "brew install ideviceinstaller").
Subprocess boundaries also keep license obligations out of this
package (libimobiledevice binaries are LGPL, ideviceinstaller is
GPL-2.0; process invocation creates no derivative work).

Tool invocations this module owns:

    list devices   idevice_id -l
    device name    ideviceinfo -u <udid> -k DeviceName
    product type   ideviceinfo -u <udid> -k ProductType
    product ver.   ideviceinfo -u <udid> -k ProductVersion
    pairing        idevicepair -u <udid> validate | pair
    developer mode ideviceinfo -u <udid> -q com.apple.security.mac.amfi
                     -k DeveloperModeStatus

UDID normalization: lockdownd reports UDIDs like 00008101-000000000000000E
(8 hex, hyphen, 16 hex). Apple device registration accepts this form
verbatim (AltStore passes it unchanged); comparisons strip the hyphen.

Ownership: DEVICE agent.
"""

from __future__ import annotations

import subprocess
import time
from collections.abc import Sequence

from sideload import config
from sideload.errors import DeviceError, NoDeviceFoundError, TransportError
from sideload.models import IOSDevice

# lockdown query domain and key for the iOS 16+ developer mode flag.
DEVELOPER_MODE_DOMAIN = "com.apple.security.mac.amfi"
DEVELOPER_MODE_KEY = "DeveloperModeStatus"

# lockdown query domain and keys for the doctor disk space report.
DISK_USAGE_DOMAIN = "com.apple.disk_usage"
DISK_KEY_FREE = "TotalDataAvailable"
DISK_KEY_TOTAL = "TotalDiskCapacity"

TOOL_HINT = "brew install libimobiledevice"

# Generous default for one shot probes; pairing and installs manage
# their own waits and run without a subprocess timeout.
DEFAULT_TIMEOUT_SECONDS = 30.0


def _run_subprocess(
    cmd: Sequence[str], timeout: float | None = DEFAULT_TIMEOUT_SECONDS
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


def normalize_udid(udid: str) -> str:
    """Lowercase and strip hyphens for UDID comparisons only."""
    return udid.strip().lower().replace("-", "")


class LibimobiledeviceTransport:
    """Subprocess based transport over the libimobiledevice tools."""

    def _tool_path(self, name: str) -> str:
        """Resolve one tool or raise a TransportError naming it."""
        path = config.find_tool(name)
        if path is None:
            raise TransportError(
                f"required tool '{name}' was not found on this Mac",
                hint=TOOL_HINT,
            )
        return path

    def _run(
        self,
        tool: str,
        args: Sequence[str],
        timeout: float | None = DEFAULT_TIMEOUT_SECONDS,
    ) -> subprocess.CompletedProcess[str]:
        cmd = [self._tool_path(tool), *[str(arg) for arg in args]]
        try:
            return _run_subprocess(cmd, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            raise DeviceError(
                f"'{tool}' did not answer within {timeout} seconds"
            ) from exc
        except OSError as exc:
            raise TransportError(
                f"could not execute '{cmd[0]}': {exc}", hint=TOOL_HINT
            ) from exc

    # ------------------------------------------------------------ devices

    def list_devices(self) -> list[IOSDevice]:
        """All USB devices currently visible to usbmuxd.

        Uses idevice_id -l. Raises TransportError when idevice_id is
        missing (hint: brew install libimobiledevice).
        """
        proc = self._run(config.TOOL_IDEVICE_ID, ["-l"])
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout).strip()
            raise DeviceError(
                f"idevice_id failed: {detail or f'exit code {proc.returncode}'}",
                hint="check that usbmuxd is running",
            )
        udid_lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
        seen: set[str] = set()
        devices: list[IOSDevice] = []
        for udid in udid_lines:
            if udid in seen:
                continue
            seen.add(udid)
            devices.append(IOSDevice(udid=udid))
        return devices

    def _ideviceinfo_value(
        self, udid: str, key: str, domain: str | None = None
    ) -> str | None:
        """One lockdown value; None when the query is refused (unpaired,
        locked, or the key does not exist on this iOS version).
        """
        args = ["-u", udid]
        if domain:
            args += ["-q", domain]
        args += ["-k", key]
        proc = self._run(config.TOOL_IDEVICEINFO, args)
        if proc.returncode != 0:
            detail = f"{proc.stderr}\n{proc.stdout}".lower()
            if "not found" in detail:
                raise NoDeviceFoundError(
                    f"no USB device with UDID {udid}",
                    hint="plug the device in over USB and unlock it",
                )
            return None
        value = proc.stdout.strip()
        return value or None

    def read_device(self, udid: str) -> IOSDevice:
        """Populate name, product type, version, pairing state, and
        developer mode for one device via ideviceinfo and idevicepair.
        """
        name = self._ideviceinfo_value(udid, "DeviceName")
        product_type = self._ideviceinfo_value(udid, "ProductType")
        product_version = self._ideviceinfo_value(udid, "ProductVersion")
        return IOSDevice(
            udid=udid,
            name=name,
            product_type=product_type,
            product_version=product_version,
            paired=self.is_paired(udid),
            developer_mode_enabled=self.developer_mode_enabled(udid),
        )

    # ------------------------------------------------------------ pairing

    def is_paired(self, udid: str) -> bool:
        """idevicepair validate result for the device."""
        proc = self._run(config.TOOL_IDEVICEPAIR, ["-u", udid, "validate"])
        if proc.returncode == 0 and "SUCCESS" in proc.stdout:
            return True
        detail = f"{proc.stdout}\n{proc.stderr}"
        if "No device found" in detail:
            raise NoDeviceFoundError(
                f"no USB device with UDID {udid}",
                hint="plug the device in over USB and unlock it",
            )
        return False

    def wait_for_pair(self, udid: str, timeout_seconds: float) -> bool:
        """Run idevicepair pair, prompting the user to tap Trust on the
        device; returns True once paired. Never auto-trusts silently.

        idevicepair pair blocks while the Trust dialog is up; this loop
        keeps retrying until the user answers, a hard failure (denied
        dialog, unsupported connection) occurs, or the budget expires.
        """
        deadline = time.monotonic() + max(timeout_seconds, 0.0)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0.0:
                return False
            try:
                proc = self._run(
                    config.TOOL_IDEVICEPAIR, ["-u", udid, "pair"], timeout=remaining
                )
            except DeviceError:
                return False
            if proc.returncode == 0 and "SUCCESS" in proc.stdout:
                return True
            detail = f"{proc.stdout}\n{proc.stderr}"
            if "No device found" in detail:
                raise NoDeviceFoundError(
                    f"no USB device with UDID {udid}",
                    hint="plug the device in over USB and unlock it",
                )
            if "denied the trust dialog" in detail:
                return False
            if "not possible over this connection" in detail:
                return False
            pause = min(2.0, max(remaining, 0.0))
            if pause > 0.0:
                time.sleep(pause)

    # ----------------------------------------------------- developer mode

    def developer_mode_enabled(self, udid: str) -> bool | None:
        """DeveloperModeStatus from lockdown; None when unavailable
        (device off, iOS older than 16, or query refused).
        """
        value = self._ideviceinfo_value(
            udid, DEVELOPER_MODE_KEY, domain=DEVELOPER_MODE_DOMAIN
        )
        if value is None:
            return None
        lowered = value.strip().lower()
        if lowered in {"enabled", "true", "1", "yes"}:
            return True
        if lowered in {"disabled", "false", "0", "no"}:
            return False
        return None

    # -------------------------------------------------- doctor diagnostics

    def disk_usage(self, udid: str) -> tuple[int, int] | None:
        """(free bytes, total bytes) from the lockdown disk usage domain,
        or None when unavailable. Used by "sideload doctor".
        """
        free_raw = self._ideviceinfo_value(udid, DISK_KEY_FREE, domain=DISK_USAGE_DOMAIN)
        total_raw = self._ideviceinfo_value(udid, DISK_KEY_TOTAL, domain=DISK_USAGE_DOMAIN)
        if free_raw is None or total_raw is None:
            return None
        try:
            free = int(free_raw.strip())
            total = int(total_raw.strip())
        except ValueError:
            return None
        if total <= 0:
            return None
        return free, total

    def list_device_profiles(self, udid: str) -> list[tuple[str, str]]:
        """(uuid, name) of every provisioning profile installed on the
        device, via ideviceprovision list. GLUE addition for
        "sideload doctor": a TransportError propagates when
        ideviceprovision is missing; other probe failures yield [].
        """
        proc = self._run(config.TOOL_IDEVICEPROVISION, ["-u", udid, "list"])
        if proc.returncode != 0:
            return []
        profiles: list[tuple[str, str]] = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith(("Device has", "ERROR")):
                continue
            if " - " in line:
                uuid, _, name = line.partition(" - ")
                profiles.append((uuid.strip(), name.strip()))
        return profiles
