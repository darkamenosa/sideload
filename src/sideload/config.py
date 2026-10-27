"""Filesystem layout and external tool discovery.

All persistent state lives under ~/Library/Application Support/sideload
following macOS conventions; nothing is written anywhere else except
the keychain (see keychain.py) and temporary directories.

Layout:
    <app_dir>/accounts/<dsid>/appids.json      cached App ID list
    <app_dir>/accounts/<dsid>/devices.json    cached team devices
    <app_dir>/accounts/<dsid>/profiles/<uuid>.mobileprovision
    <app_dir>/installs/<udid>.json             per device install records
    <app_dir>/logs/                            rotating command logs

Ownership: shared (GLUE agent).
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

# External tools the device layer drives as subprocesses.
TOOL_IDEVICE_ID = "idevice_id"
TOOL_IDEVICEINFO = "ideviceinfo"
TOOL_IDEVICEPAIR = "idevicepair"
TOOL_IDEVICEINSTALLER = "ideviceinstaller"
TOOL_IDEVICEPROVISION = "ideviceprovision"
TOOL_IDEVICESYSLOG = "idevicesyslog"
TOOL_CODESIGN = "codesign"
TOOL_SECURITY = "security"
TOOL_LDID = "ldid"

# Tools that must exist for full functionality. Missing tools are a
# TransportError at runtime, not an import time failure.
REQUIRED_TOOLS: tuple[str, ...] = (
    TOOL_IDEVICE_ID,
    TOOL_IDEVICEINFO,
    TOOL_IDEVICEPAIR,
    TOOL_IDEVICEINSTALLER,
    TOOL_CODESIGN,
    TOOL_SECURITY,
)

# Tools with documented fallbacks. ldid is only needed when keychain
# signing is unavailable; ideviceprovision only for "sideload doctor".
# GLUE addition: idevicesyslog is only needed for
# "sideload doctor --follow-logs".
OPTIONAL_TOOLS: tuple[str, ...] = (TOOL_LDID, TOOL_IDEVICEPROVISION, TOOL_IDEVICESYSLOG)

# Environment override so tests and CI never touch the real user state.
ENV_SIDELOAD_HOME = "SIDELOAD_HOME"

# Fallback locations checked after PATH so Homebrew tools are found
# even from GUI launched shells that carry a minimal PATH.
TOOL_FALLBACK_DIRS: tuple[Path, ...] = (Path("/opt/homebrew/bin"), Path("/usr/local/bin"))

HOMEBREW_LIBIMOBILEDEVICE = "brew install libimobiledevice"

# Install hint per tool, used by "auth status" and "doctor" output.
TOOL_INSTALL_HINTS: dict[str, str] = {
    TOOL_IDEVICE_ID: HOMEBREW_LIBIMOBILEDEVICE,
    TOOL_IDEVICEINFO: HOMEBREW_LIBIMOBILEDEVICE,
    TOOL_IDEVICEPAIR: HOMEBREW_LIBIMOBILEDEVICE,
    TOOL_IDEVICEPROVISION: HOMEBREW_LIBIMOBILEDEVICE,
    TOOL_IDEVICESYSLOG: HOMEBREW_LIBIMOBILEDEVICE,
    TOOL_IDEVICEINSTALLER: "brew install ideviceinstaller",
    TOOL_CODESIGN: "install Xcode or run: xcode-select --install",
    TOOL_SECURITY: "install Xcode or run: xcode-select --install",
    TOOL_LDID: "brew install ldid",
}

CONFIG_FILE_NAME = "config.json"


@dataclass(frozen=True)
class AppPaths:
    """Resolved filesystem layout for one sideload install."""

    root: Path
    accounts_dir: Path
    installs_dir: Path
    logs_dir: Path
    cache_dir: Path

    def account_dir(self, dsid: str) -> Path:
        """Directory holding cached developer resources for one account."""
        return self.accounts_dir / _safe_component(dsid, "dsid")

    def install_records_path(self, udid: str) -> Path:
        """Path of the per device install record file."""
        return self.installs_dir / f"{_safe_component(udid, 'udid')}.json"


@dataclass(frozen=True)
class SideloadConfig:
    """Persistent CLI preferences stored as <root>/config.json.

    GLUE addition to the pinned skeleton. The Keychain session is
    stored per Apple ID email (keychain.load_session(email)), so the
    CLI must remember which email is logged in for "auth status" and
    "auth logout". selected_team and default_device are the pinned
    preferences; rotate_certificate persists the
    "auth login --rotate-certificate" opt in for the next sign run.

    Persistence format is JSON: the stdlib round trips it without a
    new dependency (TOML writing would need a third party writer).
    """

    email: str | None = None
    selected_team: str | None = None
    default_device: str | None = None
    rotate_certificate: bool = False


def _safe_component(value: str, label: str) -> str:
    """Sanitize one path component built from an external identifier."""
    cleaned = value.strip().replace("/", "-").replace("\\", "-").replace("\x00", "")
    if not cleaned or cleaned in {".", ".."}:
        raise ValueError(f"invalid {label}: {value!r}")
    return cleaned


def get_paths() -> AppPaths:
    """Resolve the sideload state layout, honoring SIDELOAD_HOME override.

    The override keeps tests and CI from touching the real user state.
    Does not create directories; call ensure_dirs afterwards.
    """
    override = os.environ.get(ENV_SIDELOAD_HOME)
    if override:
        root = Path(override).expanduser()
    else:
        root = Path.home() / "Library" / "Application Support" / "sideload"
    return AppPaths(
        root=root,
        accounts_dir=root / "accounts",
        installs_dir=root / "installs",
        logs_dir=root / "logs",
        cache_dir=root / "cache",
    )


def ensure_dirs(paths: AppPaths) -> None:
    """Create the state directories with 0700 permissions."""
    directories = (
        paths.root,
        paths.accounts_dir,
        paths.installs_dir,
        paths.logs_dir,
        paths.cache_dir,
    )
    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)
        os.chmod(directory, 0o700)


def find_tool(name: str) -> str | None:
    """Return the absolute path of an external tool, or None.

    Resolution order: PATH, then /opt/homebrew/bin, then /usr/local/bin,
    so Homebrew tools are found even from GUI launched shells.
    """
    resolved = shutil.which(name)
    if resolved is not None:
        return resolved
    for directory in TOOL_FALLBACK_DIRS:
        candidate = directory / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def check_tools() -> dict[str, str | None]:
    """Map every tool name from REQUIRED_TOOLS and OPTIONAL_TOOLS to its
    resolved path or None, for "sideload auth status" and doctor output.
    """
    resolved: dict[str, str | None] = {}
    for name in (*REQUIRED_TOOLS, *OPTIONAL_TOOLS):
        resolved[name] = find_tool(name)
    return resolved


def config_path(paths: AppPaths) -> Path:
    """Location of the persisted CLI preferences file."""
    return paths.root / CONFIG_FILE_NAME


def load_config(paths: AppPaths) -> SideloadConfig:
    """Load CLI preferences; missing or corrupt files yield defaults."""
    raw = load_json(config_path(paths))
    if raw is None:
        return SideloadConfig()
    email = raw.get("email")
    selected_team = raw.get("selected_team")
    default_device = raw.get("default_device")
    rotate = raw.get("rotate_certificate")
    return SideloadConfig(
        email=email if isinstance(email, str) and email else None,
        selected_team=selected_team if isinstance(selected_team, str) and selected_team else None,
        default_device=default_device if isinstance(default_device, str) and default_device else None,
        rotate_certificate=rotate is True,
    )


def save_config(paths: AppPaths, settings: SideloadConfig) -> None:
    """Persist CLI preferences with an atomic 0600 write."""
    payload: dict[str, object] = {
        "email": settings.email,
        "selected_team": settings.selected_team,
        "default_device": settings.default_device,
        "rotate_certificate": settings.rotate_certificate,
    }
    atomic_write_json(config_path(paths), payload)


# ------------------------------------------------------------ atomic writes


def atomic_write_bytes(path: Path, data: bytes, mode: int = 0o600) -> None:
    """Write bytes to path via a same directory temp file plus os.replace.

    Readers never observe a half written file. The temp file is created
    with mkstemp (0600) and chmod'ed to mode before the rename, so the
    final file always carries the requested permissions.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temp_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temp_path = Path(temp_name)
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp_path, mode)
        os.replace(temp_path, path)
    except BaseException:
        temp_path.unlink(missing_ok=True)
        raise


def atomic_write_text(path: Path, text: str, mode: int = 0o600) -> None:
    """UTF-8 text variant of atomic_write_bytes."""
    atomic_write_bytes(path, text.encode("utf-8"), mode)


def atomic_write_json(path: Path, payload: object, mode: int = 0o600) -> None:
    """JSON variant of atomic_write_bytes (indent 2, sorted keys)."""
    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    atomic_write_text(path, text, mode)


def load_json(path: Path) -> dict[str, object] | None:
    """Read a JSON object; None when absent or unreadable."""
    if not path.is_file():
        return None
    try:
        with path.open("r", encoding="utf-8") as stream:
            raw = json.load(stream)
    except (OSError, ValueError):
        _quarantine_corrupt(path)
        return None
    if not isinstance(raw, dict):
        _quarantine_corrupt(path)
        return None
    return raw


def load_json_list(path: Path) -> list[object]:
    """Read a JSON array; empty list when absent or unreadable."""
    if not path.is_file():
        return []
    try:
        with path.open("r", encoding="utf-8") as stream:
            raw = json.load(stream)
    except (OSError, ValueError):
        _quarantine_corrupt(path)
        return []
    if not isinstance(raw, list):
        _quarantine_corrupt(path)
        return []
    return raw


def _quarantine_corrupt(path: Path) -> None:
    """Rename an unreadable cache file instead of silently overwriting it."""
    try:
        path.replace(path.with_name(path.name + ".corrupt"))
    except OSError:
        pass
