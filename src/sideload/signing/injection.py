"""Dylib and .deb tweak injection into an extracted IPA.

Semantics match Sideloadly's injection feature:

    1. A dylib is copied into the main app bundle's Frameworks
       directory (created when absent) and the main executable gains
       one LC_LOAD_DYLIB load command pointing at
       "@executable_path/Frameworks/<filename>", so the dylib loads
       at launch.
    2. A .deb tweak is unpacked in memory: the ar archive and its
       data.tar (xz, gzip, or lzma) are extracted and every
       Library/MobileSubstrate/DynamicLibraries/*.dylib member is
       injected the same way. The sibling .plist filter is read and a
       basic bundle id check is applied; nothing is installed on the
       device and no package is extracted besides the dylibs.

Scheduling contract: injection runs after ipa.extract_ipa and before
entitlements are read and signer.sign_bundle runs. The copied dylib
is a loose Mach-O file inside Frameworks, so
AppBundle.signable_inventory() picks it up automatically and the
signer signs it before the app executable.

Mach-O editing uses LIEF (MIT, a pyproject dependency), which appends
the load command to every slice of a universal binary and rewrites the
fat header offsets, so thin arm64 and universal executables both work
without hand rolling a header shifter. insert_dylib and optool are not
vendored or required; LIEF is imported lazily so every non injection
code path runs without it.

Idempotence: the executable's existing LC_LOAD_DYLIB install names are
checked before editing. A dylib whose install name is already linked
refreshes the Frameworks copy and adds no second load command.
"""

from __future__ import annotations

import gzip
import io
import lzma
import os
import plistlib
import shutil
import stat
import tarfile
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from sideload.errors import IPAError, SigningError, UnsupportedIPAError
from sideload.signing.ipa import AppBundle, IPABundle, is_macho_file

Notify = Callable[[str], None]

FRAMEWORKS_DIR = "Frameworks"
_TWEAK_DIR = PurePosixPath("Library/MobileSubstrate/DynamicLibraries")

# Debian package limits; the archives are untrusted input, so the raw
# deb, the decompressed data.tar, and each extracted dylib are bounded.
MAX_DEB_BYTES = 1 << 30
MAX_TWEAK_TAR_BYTES = 1 << 30
MAX_TWEAK_MEMBER_BYTES = 256 << 20
_MAX_AR_MEMBERS = 64

_AR_MAGIC = b"!<arch>\n"
_AR_HEADER_SIZE = 60

# data.tar members this module can unpack, most common first.
_DATA_FLAVORS: dict[str, str] = {
    "data.tar.xz": "xz",
    "data.tar.gz": "gz",
    "data.tar.lzma": "lzma",
    "data.tar": "plain",
}

_HINT_NOT_A_DEB = (
    "a .deb is an ar archive containing data.tar and control.tar; "
    "pass a Debian package file"
)
_HINT_NO_ARM64 = (
    "iOS apps load arm64 code; rebuild the dylib for arm64 or as a "
    "universal binary that contains an arm64 slice"
)


# ------------------------------------------------------------------ LIEF


def _lief_module() -> Any:
    """Import LIEF lazily so non injection code paths need no LIEF."""
    try:
        import lief  # deferred: only dylib injection needs it
    except ImportError as exc:
        raise SigningError(
            "the LIEF library is required to inject dylibs",
            hint="install this project with its dependencies (pip install lief)",
        ) from exc
    return lief


def _parse_macho(path: Path, lief: Any) -> Any:
    """The parsed FatBinary for any Mach-O file, thin or universal."""
    try:
        fat = lief.MachO.parse(str(path))
    except Exception as exc:  # LIEF raises bare runtime errors
        raise IPAError(
            f"{path} could not be parsed as a Mach-O binary: {exc}"
        ) from exc
    if fat is None:
        raise IPAError(
            f"{path} is not a Mach-O binary",
            hint="pass a dylib or executable built for iOS (arm64 or universal)",
        )
    return fat


def _slices(fat: Any) -> list[Any]:
    """Every non null Binary slice of a FatBinary."""
    binaries: list[Any] = []
    for index in range(len(fat)):
        binary = fat.at(index)
        if binary is not None:
            binaries.append(binary)
    return binaries


def _cpu_name(cpu: Any, lief: Any) -> str:
    """A human architecture name for a LIEF CPU_TYPE value."""
    names = {
        lief.MachO.Header.CPU_TYPE.ARM64: "arm64",
        lief.MachO.Header.CPU_TYPE.X86_64: "x86_64",
        lief.MachO.Header.CPU_TYPE.X86: "i386",
        lief.MachO.Header.CPU_TYPE.ARM: "arm",
        lief.MachO.Header.CPU_TYPE.POWERPC: "ppc",
        lief.MachO.Header.CPU_TYPE.POWERPC64: "ppc64",
    }
    return names.get(cpu, str(cpu).rsplit(".", 1)[-1])


def _macho_archs(path: Path, lief: Any) -> list[str]:
    """The architecture name of every slice, for error messages."""
    binaries = _slices(_parse_macho(path, lief))
    return [_cpu_name(binary.header.cpu_type, lief) for binary in binaries]


def _require_arm64(path: Path, lief: Any, what: str) -> None:
    """Reject binaries without an arm64 slice with a clear error."""
    archs = _macho_archs(path, lief)
    if not any(arch == "arm64" for arch in archs):
        found = ", ".join(archs) if archs else "none"
        raise UnsupportedIPAError(
            f"{what} {path.name} has no arm64 slice (found: {found})",
            hint=_HINT_NO_ARM64,
        )


def _load_dylib_names(path: Path, lief: Any) -> list[str]:
    """Every LC_LOAD_DYLIB and LC_LOAD_WEAK_DYLIB install name.

    Returns an empty list when the file cannot be parsed; the caller
    then proceeds to the edit step, which reports the parse failure.
    """
    try:
        fat = _parse_macho(path, lief)
    except IPAError:
        return []
    names: list[str] = []
    for binary in _slices(fat):
        for command in binary.libraries:
            names.append(command.name)
    return names


def install_name_for(filename: str) -> str:
    """The install name a Frameworks dylib is loaded by."""
    return f"@executable_path/{FRAMEWORKS_DIR}/{filename}"


def _add_load_command(executable: Path, install_name: str, lief: Any) -> bool:
    """Append one LC_LOAD_DYLIB to every slice of the executable.

    LIEF shifts the existing load commands, updates ncmds and
    sizeof_cmds, and rewrites the fat header offsets, so thin and
    universal binaries both stay valid. The write goes through a temp
    file and os.replace, so a crash cannot truncate the executable.
    """
    fat = _parse_macho(executable, lief)
    binaries = _slices(fat)
    if not binaries:
        raise IPAError(f"{executable} has no readable Mach-O slice")
    changed = False
    for binary in binaries:
        existing = [command.name for command in binary.libraries]
        if install_name in existing:
            continue
        binary.add_library(install_name)
        changed = True
    if not changed:
        return False
    mode = stat.S_IMODE(executable.stat().st_mode) or 0o755
    temp = executable.with_name(f".{executable.name}.inject-{os.getpid()}.tmp")
    try:
        fat.write(str(temp))
    except Exception as exc:
        temp.unlink(missing_ok=True)
        raise SigningError(
            f"could not add the load command to {executable}: {exc}",
            hint="the executable may use Mach-O features LIEF cannot rewrite",
        ) from exc
    os.chmod(temp, mode)
    os.replace(temp, executable)
    return True


# ------------------------------------------------------------- dylib


def inject_dylib(
    bundle: AppBundle,
    dylib_path: Path,
    notify: Notify = print,
) -> Path:
    """Copy dylib_path into bundle Frameworks and link it at launch.

    Raises IPAError when the input is missing or not a Mach-O file,
    UnsupportedIPAError when neither the dylib nor the executable has
    an arm64 slice, and returns the copied Frameworks path.
    """
    dylib_path = Path(dylib_path).expanduser()
    if not dylib_path.is_file():
        raise IPAError(f"the dylib to inject was not found: {dylib_path}")
    if not is_macho_file(dylib_path):
        raise IPAError(
            f"not a Mach-O dylib: {dylib_path}",
            hint="pass a .dylib built for iOS (arm64 or universal)",
        )
    lief = _lief_module()
    _require_arm64(dylib_path, lief, "the dylib to inject")

    executable = bundle.executable
    if not is_macho_file(executable):
        raise IPAError(f"the bundle executable is not a Mach-O binary: {executable}")
    _require_arm64(executable, lief, "the app executable")

    frameworks = bundle.root / FRAMEWORKS_DIR
    try:
        frameworks.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise IPAError(
            f"could not create the Frameworks directory {frameworks}: {exc}"
        ) from exc
    destination = frameworks / dylib_path.name
    shutil.copyfile(dylib_path, destination)
    os.chmod(destination, 0o755)

    install_name = install_name_for(dylib_path.name)
    # The executable can be a symlink inside the bundle (some IPAs ship
    # them); edit the file the link points at, never the link itself.
    real_executable = executable.resolve()
    if not real_executable.is_file():
        raise IPAError(f"the bundle executable is missing: {executable}")
    if install_name in _load_dylib_names(real_executable, lief):
        notify(
            f"inject: {dylib_path.name} is already linked by {executable.name}; "
            f"refreshed {FRAMEWORKS_DIR}/{dylib_path.name}"
        )
        return destination
    _add_load_command(real_executable, install_name, lief)
    notify(f"inject: {dylib_path.name} -> {FRAMEWORKS_DIR}/{dylib_path.name}")
    return destination


# ----------------------------------------------------------- ar archive


@dataclass(frozen=True)
class _ArMember:
    """One member of a Debian package's ar archive."""

    name: str
    offset: int  # byte offset of the member data
    size: int  # byte length of the member data


def _iter_ar_members(deb_path: Path) -> list[_ArMember]:
    """Every member of the deb's ar archive, in order.

    Supports the two ar flavors debs come in: GNU (inline names with a
    trailing slash, long names through a "//" string table, the armap
    stored as "/") and BSD ("#1/<len>" names stored after the header).
    BSD is what macOS ar writes, GNU is what dpkg-deb writes.
    """
    file_size = deb_path.stat().st_size
    if file_size > MAX_DEB_BYTES:
        raise IPAError(f"refusing .deb larger than {MAX_DEB_BYTES} bytes: {deb_path}")
    members: list[_ArMember] = []
    long_names = b""
    with deb_path.open("rb") as handle:
        if handle.read(8) != _AR_MAGIC:
            raise IPAError(
                f"{deb_path} is not a Debian package: it has no ar archive header",
                hint=_HINT_NOT_A_DEB,
            )
        offset = 8
        while True:
            handle.seek(offset)
            header = handle.read(_AR_HEADER_SIZE)
            if not header:
                break
            if len(header) != _AR_HEADER_SIZE:
                raise IPAError(f"{deb_path} has a truncated ar member header")
            if header[58:60] != b"`\n":
                raise IPAError(
                    f"{deb_path} is not a valid ar archive (bad member header at byte {offset})"
                )
            raw_name = header[:16].decode("ascii", "replace").rstrip()
            try:
                member_size = int(header[48:58].decode("ascii", "replace").strip())
            except ValueError as exc:
                raise IPAError(f"{deb_path} has an unreadable ar member size") from exc
            if member_size < 0:
                raise IPAError(f"{deb_path} declares a negative ar member size")
            data_offset = offset + _AR_HEADER_SIZE
            if data_offset + member_size > file_size:
                raise IPAError(f"{deb_path} declares an ar member past the file end")
            if len(members) >= _MAX_AR_MEMBERS:
                raise IPAError(f"refusing .deb with more than {_MAX_AR_MEMBERS} ar members")
            if raw_name.startswith("#1/"):
                # BSD inline name; the name bytes belong to the member size.
                try:
                    name_len = int(raw_name[3:])
                except ValueError as exc:
                    raise IPAError(
                        f"{deb_path} has a malformed BSD ar member name"
                    ) from exc
                if name_len <= 0 or name_len > member_size:
                    raise IPAError(f"{deb_path} has a malformed BSD ar member name")
                handle.seek(data_offset)
                name = handle.read(name_len).decode("utf-8", "replace").rstrip("\x00")
                data_offset += name_len
                member_size -= name_len
            elif raw_name == "//":
                # GNU long name string table.
                handle.seek(data_offset)
                long_names = handle.read(min(member_size, 1 << 20))
                name = "//"
            elif raw_name == "/":
                name = "/"  # GNU armap; skipped by name matching
            elif raw_name.startswith("/"):
                name = _gnu_long_name(raw_name, long_names, deb_path)
            else:
                # GNU inline names carry a trailing slash; BSD plain
                # names are padded with spaces, already stripped.
                name = raw_name.removesuffix("/")
            members.append(_ArMember(name, data_offset, member_size))
            offset = data_offset + member_size + (member_size & 1)
    return members


def _gnu_long_name(raw_name: str, table: bytes, deb_path: Path) -> str:
    """Resolve a "/<offset>" GNU member name through the string table."""
    try:
        index = int(raw_name[1:])
    except ValueError as exc:
        raise IPAError(
            f"{deb_path} has a malformed GNU ar member name: {raw_name!r}"
        ) from exc
    if index >= len(table):
        raise IPAError(f"{deb_path} has a long ar member name past its string table")
    end = table.find(b"\n", index)
    name = table[index : end if end != -1 else len(table)]
    return name.decode("utf-8", "replace").rstrip("/")


def _select_data_member(members: Sequence[_ArMember], deb_path: Path) -> _ArMember:
    """Pick the data.tar member, or fail with a clear error."""
    by_name = {
        member.name: member for member in members if member.name.startswith("data.tar")
    }
    if not by_name:
        raise IPAError(f"{deb_path} contains no data.tar member", hint=_HINT_NOT_A_DEB)
    for flavor in _DATA_FLAVORS:
        member = by_name.get(flavor)
        if member is not None:
            return member
    found = ", ".join(sorted(by_name))
    raise UnsupportedIPAError(
        f"{deb_path} uses an unsupported data archive ({found})",
        hint="repack the .deb with an xz, gzip, or lzma compressed data.tar",
    )


# ------------------------------------------------------------- tar


class _SliceReader(io.RawIOBase):
    """A read only stream over one byte range of a file."""

    def __init__(self, path: Path, offset: int, size: int) -> None:
        super().__init__()
        self._handle = path.open("rb")
        self._handle.seek(offset)
        self._remaining = size

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:  # io.RawIOBase protocol
        if self._remaining <= 0:
            return 0
        data = self._handle.read(min(len(buffer), self._remaining))
        self._remaining -= len(data)
        buffer[: len(data)] = data
        return len(data)

    def close(self) -> None:
        self._handle.close()
        super().close()


class _BoundedReader(io.RawIOBase):
    """A read only stream that refuses to yield more than cap bytes."""

    def __init__(self, stream: io.BufferedIOBase, cap: int) -> None:
        super().__init__()
        self._stream = stream
        self._cap = cap
        self._total = 0

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:  # io.RawIOBase protocol
        data = self._stream.read(len(buffer))
        self._total += len(data)
        if self._total > self._cap:
            raise OSError(
                f"the decompressed data archive exceeds {_format_bytes(self._cap)}"
            )
        buffer[: len(data)] = data
        return len(data)

    def close(self) -> None:
        self._stream.close()
        super().close()


def _format_bytes(size: int) -> str:
    value = float(size)
    for unit in ("bytes", "KiB", "MiB", "GiB"):
        if value < 1024.0 or unit == "GiB":
            return f"{value:.0f} {unit}"
        value /= 1024.0
    return f"{value:.0f} bytes"


def _tweak_relative_name(name: str) -> str | None:
    """A safe relative tar name, or None when it must be skipped.

    Only files directly under Library/MobileSubstrate/
    DynamicLibraries matter; anything absolute, traversing, or with a
    backslash is rejected.
    """
    name = name.removeprefix("./")
    if not name or name.startswith("/"):
        return None
    if "\\" in name:
        return None
    relative = PurePosixPath(name)
    if relative.is_absolute():
        return None
    if any(part in {"", ".."} for part in relative.parts):
        return None
    return name


def _open_data_tar(deb_path: Path, member: _ArMember) -> io.BufferedIOBase:
    """The decompressed data.tar as a stream, bounded per flavor."""
    buffered = io.BufferedReader(_SliceReader(deb_path, member.offset, member.size))
    flavor = _DATA_FLAVORS[member.name]
    if flavor == "xz":
        return lzma.LZMAFile(buffered, format=lzma.FORMAT_XZ)
    if flavor == "lzma":
        return lzma.LZMAFile(buffered, format=lzma.FORMAT_ALONE)
    if flavor == "gz":
        return gzip.GzipFile(fileobj=buffered)
    return buffered


def _extract_tweak_files(
    deb_path: Path, member: _ArMember, dest_dir: Path
) -> tuple[list[Path], dict[str, Path]]:
    """Every tweak dylib and filter plist inside data.tar.

    Returns the extracted dylib paths plus a map from dylib stem to
    its sibling .plist filter path.
    """
    stream = _BoundedReader(_open_data_tar(deb_path, member), MAX_TWEAK_TAR_BYTES)
    dylibs: list[Path] = []
    plists: dict[str, Path] = {}
    try:
        with tarfile.open(fileobj=stream, mode="r|") as tar:
            for entry in tar:
                if not entry.isfile():
                    continue
                name = _tweak_relative_name(entry.name)
                if name is None:
                    continue
                relative = PurePosixPath(name)
                if relative.parent != _TWEAK_DIR:
                    continue
                base = relative.name
                if base in {".", ".."}:
                    continue
                if entry.size > MAX_TWEAK_MEMBER_BYTES:
                    raise IPAError(
                        f"the tweak member {entry.name} is larger than "
                        f"{_format_bytes(MAX_TWEAK_MEMBER_BYTES)}"
                    )
                source = tar.extractfile(entry)
                if source is None:
                    continue
                target = dest_dir / base
                with open(target, "wb") as handle:
                    shutil.copyfileobj(source, handle, length=1 << 20)
                if base.endswith(".dylib"):
                    dylibs.append(target)
                elif base.endswith(".plist"):
                    plists[base[: -len(".plist")]] = target
    except (tarfile.ReadError, EOFError) as exc:
        raise IPAError(
            f"the data archive inside {deb_path.name} is malformed or larger than "
            f"{_format_bytes(MAX_TWEAK_TAR_BYTES)}: {exc}"
        ) from exc
    finally:
        stream.close()
    return dylibs, plists


# ------------------------------------------------------------- filters


def _filter_allows(
    plist_path: Path,
    bundle_ids: Sequence[str],
    dylib_name: str,
    notify: Notify,
) -> bool:
    """A basic bundle id check for a MobileSubstrate filter plist.

    True means inject. When the plist carries a Bundles list, the
    tweak is injected only when it mentions a bundle id of this app;
    filters sideload cannot evaluate (Classes, Executables, or none at
    all) are announced as ignored and the dylib is injected anyway,
    because the user explicitly asked for it.
    """
    try:
        raw = plist_path.read_bytes()
        parsed = plistlib.loads(raw)
    except (OSError, ValueError):
        # plistlib and the XML plist parser both raise ValueError
        # subclasses on malformed input; read errors are OSError.
        notify(f"warning: the filter {plist_path.name} could not be read and is ignored")
        return True
    if not isinstance(parsed, dict):
        notify(f"warning: the filter {plist_path.name} is malformed and is ignored")
        return True
    filter_dict = parsed.get("Filter")
    if not isinstance(filter_dict, dict):
        notify(
            f"warning: the filter {plist_path.name} has no Filter dict and is ignored"
        )
        return True
    bundles = filter_dict.get("Bundles")
    if bundles is None:
        notify(
            f"warning: {plist_path.name} filters on classes or executables, which "
            "sideload cannot check; the filter is ignored"
        )
        return True
    if isinstance(bundles, str):
        bundles = [bundles]
    if not isinstance(bundles, list) or not all(
        isinstance(item, str) for item in bundles
    ):
        notify(
            f"warning: the Bundles filter in {plist_path.name} is malformed and is ignored"
        )
        return True
    matched = [item for item in bundles if item in bundle_ids]
    if matched:
        notify(f"filter: {plist_path.name} matches bundle id {matched[0]}")
        return True
    ids = ", ".join(sorted(set(bundle_ids))[:3]) or "(none)"
    notify(
        f"warning: the filter {plist_path.name} does not match this app's bundle "
        f"ids ({ids}); skipping {dylib_name}"
    )
    return False


# ------------------------------------------------------------- .deb


def inject_deb(
    bundle: AppBundle,
    deb_path: Path,
    bundle_ids: Sequence[str],
    notify: Notify = print,
) -> list[Path]:
    """Inject every MobileSubstrate dylib from a .deb tweak.

    Nothing is installed on the device and no package is unpacked
    except the dylibs (and the filter plists, which are read and then
    discarded). Returns the injected Frameworks paths.
    """
    deb_path = Path(deb_path).expanduser()
    if not deb_path.is_file():
        raise IPAError(f"the .deb to inject was not found: {deb_path}")
    notify(f"inject: unpacking tweaks from {deb_path.name}")
    members = _iter_ar_members(deb_path)
    member = _select_data_member(members, deb_path)
    injected: list[Path] = []
    with tempfile.TemporaryDirectory(prefix="sideload-inject-") as temp:
        dest_dir = Path(temp)
        dylibs, plists = _extract_tweak_files(deb_path, member, dest_dir)
        if not dylibs:
            raise IPAError(
                f"{deb_path} contains no tweak dylib under {_TWEAK_DIR.as_posix()}",
                hint="only Library/MobileSubstrate/DynamicLibraries/*.dylib "
                "members of a .deb are injected",
            )
        for dylib in dylibs:
            plist = plists.get(dylib.name.removesuffix(".dylib"))
            if plist is not None and not _filter_allows(
                plist, bundle_ids, dylib.name, notify
            ):
                continue
            injected.append(inject_dylib(bundle, dylib, notify))
    return injected


# ------------------------------------------------------------- entry


def apply_injections(
    bundle: IPABundle,
    dylib_paths: Sequence[Path],
    deb_paths: Sequence[Path],
    notify: Notify = print,
) -> list[Path]:
    """Inject every requested dylib and .deb tweak into the main app.

    The single entry point the CLI calls between extract_ipa and the
    sign pipeline. With both lists empty it does nothing, so the no
    flag path is unchanged.
    """
    if not dylib_paths and not deb_paths:
        return []
    bundle_ids = [
        app_bundle.bundle_identifier
        for app_bundle in bundle.all_bundles
        if app_bundle.bundle_identifier
    ]
    injected: list[Path] = []
    for dylib_path in dylib_paths:
        injected.append(inject_dylib(bundle.main_bundle, dylib_path, notify))
    for deb_path in deb_paths:
        injected.extend(inject_deb(bundle.main_bundle, deb_path, bundle_ids, notify))
    return injected