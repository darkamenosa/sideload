"""launchd refresh agent and refresh loop helpers.

Free Apple provisioning profiles expire 7 days after issuance, so a
sideloaded app stops launching after a week unless it is re-signed and
reinstalled, exactly like Sideloadly's auto refresh. This module holds
the two pieces of that automation:

    refresh helpers   per app outcome bookkeeping for
                      "sideload refresh": which records can be refreshed
                      (their recorded source IPA still exists), how the
                      summary is formatted, and which exit code the run
                      deserves
    launchd agent     plist generation, bootstrap, boot out, and status
                      for "sideload daemon install|uninstall|status",
                      so a LaunchAgent runs
                      "python -m sideload refresh --all" once a day

Background constraints, documented rather than hidden: the launchd
agent cannot prompt. No password can be typed, no 2FA code can be
entered, and no device Trust dialog can be accepted while it runs.
The refresh therefore depends on a valid Keychain session; when the
session is missing, expired, or rejected by Apple, the run exits 3 and
the refresh log tells the user to run "sideload auth login" in a
terminal.

Security: no password is ever stored (see keychain.py) and the session
token stays in the Keychain; nothing here prints tokens or passwords.
The refresh log receives only bundle ids, file paths, dates, and error
messages, so it is safe to keep on disk.

All launchctl work goes through an injectable runner and all paths
through an injectable DaemonPaths, so the tests never touch the real
launchd or the real ~/Library.
"""

from __future__ import annotations

import os
import plistlib
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from sideload import config
from sideload.errors import EXIT_ERROR, EXIT_OK, DaemonError
from sideload.models import InstallRecord

# The LaunchAgent identity. The label and the plist file name match so
# "launchctl list <label>" and the on disk file agree.
LAUNCH_AGENT_LABEL = "dev.sideload.refresh"
PLIST_FILE_NAME = "dev.sideload.refresh.plist"

# Daily cadence: profiles last 7 days, so a daily attempt refreshes in
# time even when the Mac sleeps through a day.
START_INTERVAL_SECONDS = 86400

LAUNCHCTL = "launchctl"
_LAUNCHCTL_TIMEOUT_SECONDS = 30.0

# A runner executes one launchctl invocation. Injectable so the test
# suite runs fully offline (no real launchd, no real LaunchAgents dir).
LaunchctlRunner = Callable[[Sequence[str]], "subprocess.CompletedProcess[str]"]


def _run_launchctl(cmd: Sequence[str]) -> subprocess.CompletedProcess[str]:
    """Run the real launchctl with captured output."""
    try:
        return subprocess.run(
            list(cmd),
            capture_output=True,
            check=False,
            text=True,
            errors="replace",
            timeout=_LAUNCHCTL_TIMEOUT_SECONDS,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        raise DaemonError(f"could not run launchctl: {exc}") from exc


@dataclass(frozen=True)
class DaemonPaths:
    """Where the refresh agent plist and its log live."""

    plist_path: Path
    log_path: Path


def default_daemon_paths() -> DaemonPaths:
    """The real user locations: ~/Library/LaunchAgents for the plist
    and the sideload logs directory for the refresh log.

    SIDELOAD_HOME (config.ENV_SIDELOAD_HOME) redirects both, so tests
    and CI never touch the real ~/Library.
    """
    app_paths = config.get_paths()
    if os.environ.get(config.ENV_SIDELOAD_HOME):
        launch_agents_dir = app_paths.root / "Library" / "LaunchAgents"
    else:
        launch_agents_dir = Path.home() / "Library" / "LaunchAgents"
    return DaemonPaths(
        plist_path=launch_agents_dir / PLIST_FILE_NAME,
        log_path=app_paths.logs_dir / "refresh.log",
    )


def refresh_program_arguments(python: str | None = None) -> list[str]:
    """ProgramArguments for the agent: the current interpreter running
    the unattended refresh for every device with install records.
    """
    return [python or sys.executable or "python3", "-m", "sideload", "refresh", "--all"]


def build_refresh_plist(
    program_arguments: Sequence[str],
    log_path: str | Path,
    start_interval: int = START_INTERVAL_SECONDS,
) -> dict[str, object]:
    """The LaunchAgent job description as a plist dict.

    Keys: Label, ProgramArguments, a daily StartInterval, RunAtLoad
    false (the daemon refreshes on schedule, not at login), and
    stdout plus stderr both into the refresh log.
    """
    return {
        "Label": LAUNCH_AGENT_LABEL,
        "ProgramArguments": list(program_arguments),
        "StartInterval": start_interval,
        "RunAtLoad": False,
        "StandardOutPath": str(log_path),
        "StandardErrorPath": str(log_path),
    }


def write_plist(plist_path: Path, plist: dict[str, object]) -> None:
    """Write the plist atomically: 0600 file, 0700 directory when the
    directory is created here. An existing LaunchAgents directory keeps
    its permissions.
    """
    existed = plist_path.parent.is_dir()
    plist_path.parent.mkdir(parents=True, exist_ok=True)
    if not existed:
        os.chmod(plist_path.parent, 0o700)
    config.atomic_write_bytes(plist_path, plistlib.dumps(plist), mode=0o600)


# ------------------------------------------------------ refresh loop helpers


class RefreshStatus(Enum):
    """What happened to one app during a refresh run."""

    REFRESHED = "refreshed"
    SKIPPED = "skipped"
    FAILED = "failed"


@dataclass(frozen=True)
class RefreshAppOutcome:
    """The per app result printed in the refresh summary."""

    resigned_bundle_id: str
    status: RefreshStatus
    detail: str


def source_ipa_for(record: InstallRecord) -> Path | None:
    """The recorded source IPA when it still exists, else None.

    Records are never deleted automatically when the file is gone; the
    app is reported and skipped so the user can restore the file or
    reinstall the app.
    """
    if not record.ipa_path:
        return None
    path = Path(record.ipa_path).expanduser()
    return path if path.is_file() else None


def skip_outcomes(
    records: Sequence[InstallRecord], reason: str
) -> list[RefreshAppOutcome]:
    """One skipped outcome per record, used for device level skips
    (not connected, not paired, Developer Mode off).
    """
    return [
        RefreshAppOutcome(
            resigned_bundle_id=record.resigned_bundle_id,
            status=RefreshStatus.SKIPPED,
            detail=reason,
        )
        for record in records
    ]


def refresh_exit_code(outcomes: Sequence[RefreshAppOutcome]) -> int:
    """Exit code for a finished refresh run.

    0 when every attempted app was refreshed (skips are tolerated as
    long as something was refreshed), 1 when any app failed or when
    nothing could be refreshed at all. Session expiry is exit 3 and is
    raised as SessionExpiredError before this is reached.
    """
    if any(outcome.status is RefreshStatus.FAILED for outcome in outcomes):
        return EXIT_ERROR
    if not any(outcome.status is RefreshStatus.REFRESHED for outcome in outcomes):
        return EXIT_ERROR
    return EXIT_OK


def format_refresh_summary(outcomes: Sequence[RefreshAppOutcome]) -> str:
    """The per app summary lines plus one count line."""
    counts = {status: 0 for status in RefreshStatus}
    lines = ["refresh summary:"]
    for outcome in outcomes:
        counts[outcome.status] += 1
        suffix = f" - {outcome.detail}" if outcome.detail else ""
        lines.append(
            f"  {outcome.status.value}: {outcome.resigned_bundle_id}{suffix}"
        )
    lines.append(
        f"refreshed {counts[RefreshStatus.REFRESHED]}, "
        f"skipped {counts[RefreshStatus.SKIPPED]}, "
        f"failed {counts[RefreshStatus.FAILED]}"
    )
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------ launchd agent


@dataclass(frozen=True)
class DaemonStatus:
    """What "sideload daemon status" reports."""

    plist_exists: bool
    loaded: bool


class RefreshDaemon:
    """Install, remove, and report the refresh LaunchAgent.

    Args:
        paths: where the plist and log live; defaults to the real user
            locations (SIDELOAD_HOME redirects them for tests).
        runner: launchctl executor; defaults to the real launchctl.
        uid: the launchd gui domain uid; defaults to the current user.
    """

    def __init__(
        self,
        paths: DaemonPaths | None = None,
        runner: LaunchctlRunner | None = None,
        uid: int | None = None,
    ) -> None:
        self.paths = paths if paths is not None else default_daemon_paths()
        self._runner = runner if runner is not None else _run_launchctl
        self._uid = os.getuid() if uid is None else uid

    def _gui_domain(self) -> str:
        return f"gui/{self._uid}"

    def _service_target(self) -> str:
        return f"{self._gui_domain()}/{LAUNCH_AGENT_LABEL}"

    def _run(self, args: Sequence[str]) -> subprocess.CompletedProcess[str]:
        return self._runner([LAUNCHCTL, *args])

    def is_loaded(self) -> bool:
        """True when launchd currently lists the agent."""
        return self._run(["list", LAUNCH_AGENT_LABEL]).returncode == 0

    def install(
        self,
        program_arguments: Sequence[str] | None = None,
        start_interval: int = START_INTERVAL_SECONDS,
    ) -> Path:
        """Write the plist and load it, replacing any loaded copy.

        Tries "launchctl bootstrap gui/<uid>" first and falls back to
        the legacy "launchctl load" on older macOS. Returns the plist
        path.
        """
        plist = build_refresh_plist(
            program_arguments
            if program_arguments is not None
            else refresh_program_arguments(),
            self.paths.log_path,
            start_interval=start_interval,
        )
        write_plist(self.paths.plist_path, plist)
        if self.is_loaded():
            # Replace the loaded agent so the new plist takes effect.
            self._run(["bootout", self._service_target()])
        result = self._run(["bootstrap", self._gui_domain(), str(self.paths.plist_path)])
        if result.returncode != 0:
            legacy = self._run(["load", str(self.paths.plist_path)])
            if legacy.returncode != 0 and not self.is_loaded():
                detail = " ".join(
                    part.strip()
                    for part in (result.stderr, result.stdout, legacy.stderr, legacy.stdout)
                    if part and part.strip()
                )
                raise DaemonError(
                    "launchctl could not load the refresh agent"
                    + (f": {detail}" if detail else ""),
                    hint=(
                        "load it manually: "
                        f"launchctl bootstrap {self._gui_domain()} {self.paths.plist_path}"
                    ),
                )
        return self.paths.plist_path

    def uninstall(self) -> bool:
        """Boot out the agent and remove the plist.

        Returns True when the plist existed. A missing or not loaded
        agent is not an error, so the command stays idempotent.
        """
        existed = self.paths.plist_path.is_file()
        if self.is_loaded() or existed:
            result = self._run(["bootout", self._service_target()])
            if result.returncode != 0:
                self._run(["unload", str(self.paths.plist_path)])
        if existed:
            self.paths.plist_path.unlink()
        return existed

    def status(self) -> DaemonStatus:
        """Whether the plist exists and whether launchd lists the agent."""
        return DaemonStatus(
            plist_exists=self.paths.plist_path.is_file(),
            loaded=self.is_loaded(),
        )
