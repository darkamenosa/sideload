"""IPA extraction, bundle inventory, modification, and repack.

Pipeline facts pinned from AltSign (ALTSigner.mm, NSFileManager+Apps.m,
ResignAppOperation.swift) and zsign (src/bundle.cpp):

    1. An IPA is a zip whose root contains Payload/Foo.app.
    2. Every .app under the main bundle matters: PlugIns/*.appex are
       app extensions that need their OWN bundle id of the form
       <parent>.<extension>, their own App ID and profile on free
       accounts, and their own embedded.mobileprovision.
    3. Mach-O binaries appear in four places: the CFBundleExecutable
       of each bundle, *.framework/* (framework binaries), loose dylibs
       (often under Frameworks/ or libs/), and PlugIns bundles. All of
       them must be re-signed.
    4. Info.plist edits that precede signing: CFBundleIdentifier must
       become the resigned bundle id, App Store receipt leftovers are
       removed (SC_Info/, Manifest.plist, _MASReceipt/), and AltStore
       also cleans embedded provisioning data.
    5. embedded.mobileprovision is written into every bundle root
       BEFORE CodeResources sealing (zsign bundle.cpp comment).
    6. Repack must produce a zip with the .app bundle intact and must
       not lose or reorder bundle resources.

Ownership: SIGN agent. This module must not call codesign itself;
signer.py owns signing. It only prepares bytes on disk.
"""

from __future__ import annotations

import os
import plistlib
import shutil
import stat
import struct
import tempfile
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from sideload.errors import (
    IPAError,
    NoAppBundleError,
    NotAnIPAError,
    UnsupportedIPAError,
)

# The four documented Mach-O magics plus their byte swapped forms; raw
# file prefixes cover both endiannesses of thin and fat images.
_MACHO_MAGICS = frozenset(
    {
        b"\xcf\xfa\xed\xfe",  # MH_MAGIC_64, little endian (arm64, x86_64)
        b"\xfe\xed\xfa\xcf",  # MH_MAGIC_64, big endian
        b"\xce\xfa\xed\xfe",  # MH_MAGIC, little endian
        b"\xfe\xed\xfa\xce",  # MH_MAGIC, big endian
        b"\xca\xfe\xba\xbe",  # FAT_MAGIC, big endian
        b"\xbe\xba\xfe\xca",  # FAT_MAGIC, little endian
    }
)

_BUNDLE_SUFFIXES = (".app", ".appex", ".framework")
_EXTENSION_SUFFIXES = (".app", ".appex")

_JUNK_DIR = "__MACOSX"
_ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)  # fixed date keeps repacks deterministic

# Untrusted archives: bound entry count and uncompressed size so a zip
# bomb cannot exhaust memory or the temp volume.
MAX_ARCHIVE_ENTRIES = 50_000
MAX_ENTRY_BYTES = 1 << 30
MAX_TOTAL_BYTES = 4 << 30
_MAX_MACHO_SCAN = 1 << 20  # load commands live in the first megabyte

# Extraction directories owned by this process, removed by the CLI on exit.
_ACTIVE_WORK_DIRS: set[Path] = set()


def cleanup_work_dirs() -> None:
    """Delete every extraction directory created by extract_ipa here."""
    while _ACTIVE_WORK_DIRS:
        shutil.rmtree(_ACTIVE_WORK_DIRS.pop(), ignore_errors=True)

# Mach-O load commands this module inspects.
LC_CODE_SIGNATURE = 0x1D
LC_ENCRYPTION_INFO = 0x21
LC_ENCRYPTION_INFO_64 = 0x2C

_MAX_FAT_SLICES = 16
_MAX_LOAD_COMMANDS = 256

_NOT_AN_IPA_HINT = "an IPA is a zip whose root contains a Payload directory"


# ------------------------------------------------------------- Mach-O


def is_macho_file(path: Path) -> bool:
    """True when the file starts with a Mach-O magic (fat or thin)."""
    try:
        with open(path, "rb") as handle:
            head = handle.read(4)
    except OSError:
        return False
    return head in _MACHO_MAGICS


def has_code_signature(path: Path) -> bool:
    """True when the Mach-O carries an LC_CODE_SIGNATURE load command."""
    commands = _macho_load_commands(path)
    if commands is None:
        return False
    return any(cmd == LC_CODE_SIGNATURE for cmd, _endian, _payload in commands)


def _macho_load_commands(path: Path) -> list[tuple[int, str, bytes]] | None:
    """Every load command as (cmd, endian, payload); None when not Mach-O.

    Only the header region is read, so a multi gigabyte binary is never
    pulled into memory just to inspect its load commands.
    """
    try:
        with path.open("rb") as handle:
            data = handle.read(_MAX_MACHO_SCAN)
            magic = data[:4]
            if magic in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
                endian = ">" if magic == b"\xca\xfe\xba\xbe" else "<"
                if len(data) < 8:
                    return None
                try:
                    (slice_count,) = struct.unpack_from(endian + "I", data, 4)
                except struct.error:
                    return None
                commands: list[tuple[int, str, bytes]] = []
                for index in range(min(slice_count, _MAX_FAT_SLICES)):
                    entry = 8 + index * 20
                    try:
                        _cputype, _cpusubtype, offset, size, _align = struct.unpack_from(
                            endian + "5I", data, entry
                        )
                    except struct.error:
                        break
                    if size <= 0:
                        continue
                    handle.seek(offset)
                    slice_data = handle.read(min(size, _MAX_MACHO_SCAN))
                    thin = _thin_load_commands(slice_data, 0, len(slice_data))
                    if thin:
                        commands.extend(thin)
                return commands
            return _thin_load_commands(data, 0, len(data))
    except OSError:
        return None


def _thin_load_commands(
    data: bytes, offset: int, size: int
) -> list[tuple[int, str, bytes]] | None:
    magic = data[offset : offset + 4]
    if magic == b"\xcf\xfa\xed\xfe":
        endian, is64 = "<", True
    elif magic == b"\xfe\xed\xfa\xcf":
        endian, is64 = ">", True
    elif magic == b"\xce\xfa\xed\xfe":
        endian, is64 = "<", False
    elif magic == b"\xfe\xed\xfa\xce":
        endian, is64 = ">", False
    else:
        return None
    header_size = 32 if is64 else 28
    if len(data) < offset + header_size:
        return None
    try:
        (command_count,) = struct.unpack_from(endian + "I", data, offset + 16)
    except struct.error:
        return None
    commands: list[tuple[int, str, bytes]] = []
    position = offset + header_size
    limit = len(data)
    if size:
        limit = min(limit, offset + size)
    for _index in range(min(command_count, _MAX_LOAD_COMMANDS)):
        if position + 8 > limit:
            break
        try:
            cmd, cmdsize = struct.unpack_from(endian + "2I", data, position)
        except struct.error:
            break
        if cmdsize < 8 or position + cmdsize > limit:
            break
        commands.append((cmd, endian, data[position + 8 : position + cmdsize]))
        position += cmdsize
    return commands


def _is_fairplay_encrypted(path: Path) -> bool:
    """True when the Mach-O requests FairPlay decryption (cryptid != 0).

    App Store binaries are FairPlay encrypted; re-signing them cannot
    produce runnable code pages, so they are rejected upfront
    (UnsupportedIPAError in extract_ipa).
    """
    if not is_macho_file(path):
        return False
    commands = _macho_load_commands(path)
    if commands is None:
        return False
    for cmd, endian, payload in commands:
        if cmd not in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
            continue
        if len(payload) < 12:
            continue
        try:
            (cryptid,) = struct.unpack_from(endian + "I", payload, 8)
        except struct.error:
            continue
        if cryptid != 0:
            return True
    return False


# -------------------------------------------------------------- bundles


@dataclass
class AppBundle:
    """One .app bundle (the main app or an embedded extension)."""

    root: Path
    bundle_identifier: str
    executable: Path
    info_plist_path: Path

    @property
    def kind(self) -> str:
        """The bundle directory suffix: ".app", ".appex", or ".framework"."""
        return self.root.suffix

    def nested_bundles(self) -> list[AppBundle]:
        """PlugIns/*.appex and Frameworks/*.framework bundle roots,
        deepest first.
        """
        found: list[AppBundle] = []
        self._collect_nested_bundles(self.root, found, set())
        found.sort(key=lambda bundle: self._deepest_first_key(bundle.root))
        return found

    def _collect_nested_bundles(
        self, directory: Path, found: list[AppBundle], seen: set[Path]
    ) -> None:
        try:
            resolved = directory.resolve()
        except OSError:
            return
        # Symlinks inside the archive may point back at an ancestor; a
        # visited set keeps the walk finite.
        if resolved in seen:
            return
        seen.add(resolved)
        try:
            entries = sorted(directory.iterdir())
        except OSError:
            return
        for entry in entries:
            if not entry.is_dir():
                continue
            if entry.suffix in _BUNDLE_SUFFIXES:
                bundle = _try_app_bundle(entry)
                if bundle is not None:
                    found.append(bundle)
            self._collect_nested_bundles(entry, found, seen)

    def _deepest_first_key(self, path: Path) -> tuple[int, str]:
        relative = path.relative_to(self.root)
        return (-len(relative.parts), relative.as_posix())

    def nested_machos(self) -> list[Path]:
        """All nested Mach-O files: framework binaries and loose dylibs
        found by magic bytes (feedface, feedfacf, cafebabe, cefaedfe),
        excluding bundle executables which are listed separately.

        Framework binaries stay in this list (their owning .framework
        bundles do not carry entitlements or profiles); the executables
        of .app/.appex bundles are excluded and returned through
        nested_bundles/signable_inventory instead. Loose dylibs come
        first, then framework binaries, each group deepest first.
        """
        excluded: set[Path] = {self.executable}
        for bundle in self.nested_bundles():
            if bundle.root.suffix in _EXTENSION_SUFFIXES:
                excluded.add(bundle.executable)
        loose: list[tuple[tuple[int, str], Path]] = []
        framework_binaries: list[tuple[tuple[int, str], Path]] = []
        for path in self._iter_files():
            if path.is_symlink() or path in excluded:
                continue
            if not is_macho_file(path):
                continue
            relative = path.relative_to(self.root)
            key = (-len(relative.parts), relative.as_posix())
            if _inside_framework(PurePosixPath(relative.as_posix())):
                framework_binaries.append((key, path))
            else:
                loose.append((key, path))
        loose.sort(key=lambda item: item[0])
        framework_binaries.sort(key=lambda item: item[0])
        return [path for _key, path in loose] + [
            path for _key, path in framework_binaries
        ]

    def _iter_files(self) -> Iterator[Path]:
        for dirpath, _dirnames, filenames in os.walk(self.root):
            for name in sorted(filenames):
                yield Path(dirpath) / name

    def signable_inventory(self) -> list[Path]:
        """Every path signer.py must sign, ordered deepest first:
        loose dylibs and framework binaries first, then nested bundle
        executables, then this bundle's executable last.
        """
        inventory = self.nested_machos()
        for bundle in self.nested_bundles():
            if bundle.root.suffix in _EXTENSION_SUFFIXES:
                inventory.append(bundle.executable)
        inventory.append(self.executable)
        return inventory

    def set_bundle_identifier(self, new_bundle_id: str) -> None:
        """Rewrite CFBundleIdentifier in Info.plist."""
        with open(self.info_plist_path, "rb") as handle:
            raw = handle.read()
        plist = _load_plist_dict(raw, self.info_plist_path)
        binary = raw.startswith(b"bplist00")
        plist["CFBundleIdentifier"] = new_bundle_id
        with open(self.info_plist_path, "wb") as handle:
            plistlib.dump(
                plist,
                handle,
                fmt=plistlib.FMT_BINARY if binary else plistlib.FMT_XML,
            )
        self.bundle_identifier = new_bundle_id

    def remove_appstore_artifacts(self) -> None:
        """Delete SC_Info/, _MASReceipt/, and iTunesMetadata.plist."""
        for relative in (
            "SC_Info",
            "_MASReceipt",
            "iTunesMetadata.plist",
            "Manifest.plist",
        ):
            target = self.root / relative
            if target.is_dir() and not target.is_symlink():
                shutil.rmtree(target)
            elif target.exists() or target.is_symlink():
                target.unlink()

    def embed_profile(self, profile_data: bytes) -> None:
        """Write embedded.mobileprovision into the bundle root."""
        (self.root / "embedded.mobileprovision").write_bytes(profile_data)


def _inside_framework(relative: PurePosixPath) -> bool:
    parts = relative.parts[:-1]
    return any(part.endswith(".framework") for part in parts)


def _try_app_bundle(root: Path) -> AppBundle | None:
    try:
        return _app_bundle(root)
    except IPAError:
        # A bundle directory without a readable Info.plist still has its
        # binary signed as a loose Mach-O, so it is skipped here rather
        # than failing the whole inventory.
        return None


def _app_bundle(root: Path) -> AppBundle:
    info_plist_path = root / "Info.plist"
    if not info_plist_path.is_file():
        raise IPAError(f"bundle {root} has no Info.plist")
    with open(info_plist_path, "rb") as handle:
        raw = handle.read()
    plist = _load_plist_dict(raw, info_plist_path)
    executable_name = plist.get("CFBundleExecutable")
    if not isinstance(executable_name, str) or not executable_name:
        raise IPAError(f"bundle {root} Info.plist has no CFBundleExecutable")
    if (
        executable_name in {".", ".."}
        or "/" in executable_name
        or "\\" in executable_name
        or PurePosixPath(executable_name).is_absolute()
    ):
        raise IPAError(
            f"bundle {root} has an unsafe CFBundleExecutable: {executable_name!r}"
        )
    executable = root / executable_name
    if not executable.resolve().is_relative_to(root.resolve()):
        raise IPAError(
            f"bundle {root} has a CFBundleExecutable outside the bundle: {executable_name!r}"
        )
    bundle_identifier = plist.get("CFBundleIdentifier")
    return AppBundle(
        root=root,
        bundle_identifier=(
            bundle_identifier if isinstance(bundle_identifier, str) else ""
        ),
        executable=executable,
        info_plist_path=info_plist_path,
    )


def _load_plist_dict(raw: bytes, source: Path) -> dict[str, Any]:
    try:
        parsed: object = plistlib.loads(raw)
    except (plistlib.InvalidFileException, ValueError) as exc:
        raise IPAError(f"{source} is not a readable plist: {exc}") from exc
    if not isinstance(parsed, dict):
        raise IPAError(f"{source} is not a dictionary")
    return parsed


@dataclass
class IPABundle:
    """The extracted contents of one IPA."""

    ipa_path: Path
    work_dir: Path
    main_bundle: AppBundle
    all_bundles: list[AppBundle] = field(default_factory=list)


def extract_ipa(ipa_path: Path, dest_dir: Path | None = None) -> IPABundle:
    """Unzip the IPA and inventory its bundles.

    Raises NotAnIPAError when the zip has no Payload directory and
    NoAppBundleError when Payload has no .app.
    """
    ipa_path = Path(ipa_path)
    if not ipa_path.is_file():
        raise IPAError(f"IPA file not found: {ipa_path}")
    created_here = dest_dir is None
    work_dir = (
        Path(dest_dir)
        if dest_dir is not None
        else Path(tempfile.mkdtemp(prefix="sideload-ipa-"))
    )
    if created_here:
        _ACTIVE_WORK_DIRS.add(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    try:
        archive = zipfile.ZipFile(ipa_path)
    except (zipfile.BadZipFile, OSError) as exc:
        raise IPAError(f"{ipa_path} is not a readable zip archive: {exc}") from exc
    with archive:
        if not any(_is_payload_name(name) for name in archive.namelist()):
            raise NotAnIPAError(
                f"{ipa_path} has no Payload directory", hint=_NOT_AN_IPA_HINT
            )
        try:
            _extract_archive(archive, work_dir)
        except zipfile.BadZipFile as exc:
            raise IPAError(f"the IPA archive is malformed: {exc}") from exc
    if (work_dir / "Watch").is_dir():
        raise UnsupportedIPAError(
            "watchOS companion apps are not supported by this signing flow",
            hint="remove the Watch directory from the IPA and sign the iPhone app only",
        )
    payload_dir = work_dir / "Payload"
    if not payload_dir.is_dir():
        raise NotAnIPAError(f"{ipa_path} has no Payload directory", hint=_NOT_AN_IPA_HINT)
    _remove_payload_artifacts(payload_dir)
    try:
        app_dirs = sorted(
            entry
            for entry in payload_dir.iterdir()
            if entry.is_dir() and entry.suffix == ".app"
        )
    except OSError as exc:
        raise IPAError(f"could not list {payload_dir}: {exc}") from exc
    if not app_dirs:
        raise NoAppBundleError(
            f"{ipa_path} has no .app bundle inside Payload", hint=_NOT_AN_IPA_HINT
        )
    main_bundle = _app_bundle(app_dirs[0])
    if (main_bundle.root / "Watch").is_dir():
        raise UnsupportedIPAError(
            "watchOS companion apps are not supported by this signing flow",
            hint="remove the Watch directory from the app and sign the iPhone app only",
        )
    all_bundles = [main_bundle, *main_bundle.nested_bundles()]
    if any(
        "Watch" in bundle.root.relative_to(main_bundle.root).parts
        for bundle in all_bundles[1:]
    ):
        raise UnsupportedIPAError(
            "watchOS companion apps are not supported by this signing flow",
            hint="remove the Watch directory from the app and sign the iPhone app only",
        )
    for bundle in all_bundles:
        if _is_fairplay_encrypted(bundle.executable):
            raise UnsupportedIPAError(
                f"{bundle.root.name} contains a FairPlay encrypted App Store "
                "binary that cannot be re-signed usefully",
                hint="sideload works with unsigned or re-signable IPAs; "
                "App Store downloads cannot be resigned",
            )
    return IPABundle(
        ipa_path=ipa_path,
        work_dir=work_dir,
        main_bundle=main_bundle,
        all_bundles=all_bundles,
    )


def _is_payload_name(name: str) -> bool:
    parts = PurePosixPath(name).parts
    return bool(parts) and parts[0] == "Payload" and _JUNK_DIR not in parts


def _assert_contained(root: Path, target: Path) -> None:
    """Refuse entries whose real path escapes the extraction root.

    Symlinked directories are legitimate inside app bundles, so the
    check resolves through them instead of forbidding them. Escape
    links themselves are rejected where they are created.
    """
    if not target.resolve().is_relative_to(root):
        raise IPAError(f"refusing zip entry outside the bundle: {target}")


def _extract_archive(archive: zipfile.ZipFile, dest_dir: Path) -> None:
    """Extract preserving symlinks, permissions, and bundle layout.

    Entry count and uncompressed sizes are bounded, and file data is
    streamed to disk rather than read into memory.
    """
    root = dest_dir.resolve()
    count = 0
    total_bytes = 0
    for info in archive.infolist():
        count += 1
        if count > MAX_ARCHIVE_ENTRIES:
            raise IPAError(
                f"refusing archive with more than {MAX_ARCHIVE_ENTRIES} entries"
            )
        name = info.filename
        if name.startswith("/") or "\\" in name:
            raise IPAError(f"refusing unsafe zip entry: {name}")
        parts = PurePosixPath(name).parts
        if not parts or _JUNK_DIR in parts:
            continue
        if any(part == ".." for part in parts):
            raise IPAError(f"refusing unsafe zip entry: {name}")
        if not info.is_dir():
            if info.file_size > MAX_ENTRY_BYTES:
                raise IPAError(
                    f"refusing zip entry larger than {MAX_ENTRY_BYTES} bytes: {name}"
                )
            total_bytes += info.file_size
            if total_bytes > MAX_TOTAL_BYTES:
                raise IPAError(
                    f"refusing archive larger than {MAX_TOTAL_BYTES} bytes uncompressed"
                )
        target = dest_dir.joinpath(*parts)
        _assert_contained(root, target)
        raw_mode = info.external_attr >> 16
        if info.is_dir():
            if target.exists() and not target.is_dir():
                raise IPAError(f"archive contains conflicting duplicate entry: {name}")
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        if stat.S_ISLNK(raw_mode):
            if info.file_size > 4096:
                raise IPAError(f"refusing oversized symlink entry: {name}")
            link_target = os.fsdecode(archive.read(info))
            if os.path.isabs(link_target) or ".." in PurePosixPath(link_target).parts:
                raise IPAError(f"refusing unsafe symlink in zip: {name} -> {link_target}")
            _remove_path(target)
            target.symlink_to(link_target)
            continue
        if target.is_symlink():
            target.unlink()
        elif target.is_dir():
            raise IPAError(f"archive contains conflicting duplicate entry: {name}")
        with archive.open(info) as source, open(target, "wb") as handle:
            shutil.copyfileobj(source, handle, length=1 << 20)
        permissions = stat.S_IMODE(raw_mode) & 0o777
        if not permissions:
            permissions = 0o644
        if is_macho_file(target) and not permissions & 0o111:
            # Code must stay executable for the device even when the
            # upstream zip lost the mode bits.
            permissions = 0o755
        os.chmod(target, permissions)


def _remove_path(path: Path) -> None:
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    elif path.exists() or path.is_symlink():
        path.unlink()


def _remove_payload_artifacts(payload_dir: Path) -> None:
    """Drop App Store leftovers stored next to the .app bundle."""
    for name in ("iTunesMetadata.plist", "Manifest.plist"):
        target = payload_dir / name
        if target.is_file() or target.is_symlink():
            target.unlink()


def resign_bundle_id(
    original_bundle_id: str,
    team_identifier: str,
    parent_bundle_id: str | None = None,
) -> str:
    """Compute the resigned bundle identifier for free teams.

    AltStore pins this rule (FetchProvisioningProfilesOperation.swift):
    append the team identifier as a suffix,
    "<original>.<TEAMID.lowercased()>", so the same app sideloaded by
    two accounts coexists and the App ID never collides. Extensions
    use "<parent_resigned>.<extension_name>".
    """
    if not original_bundle_id:
        raise IPAError("cannot resign an empty bundle identifier")
    if parent_bundle_id is not None:
        extension_name = original_bundle_id.rsplit(".", 1)[-1]
        return f"{parent_bundle_id}.{extension_name}"
    if not team_identifier:
        raise IPAError("cannot resign without a team identifier")
    return f"{original_bundle_id}.{team_identifier.lower()}"


def repack_ipa(bundle: IPABundle, output_path: Path) -> Path:
    """Zip the prepared Payload back into an installable IPA.

    The archive is deterministic: fixed timestamps, sorted entries, no
    __MACOSX junk, no .DS_Store droppings, symlinks and unix
    permissions preserved bit for bit.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    entries: list[tuple[str, int, Path | None, str | None]] = []
    _collect_archive_entries(bundle.work_dir, entries)
    entries.sort(key=lambda entry: entry[0])
    fd, temp_name = tempfile.mkstemp(
        prefix=f".{output_path.name}.", suffix=".tmp", dir=output_path.parent
    )
    os.close(fd)
    temp_path = Path(temp_name)
    try:
        with zipfile.ZipFile(
            temp_path, "w", compression=zipfile.ZIP_DEFLATED
        ) as archive:
            for arcname, mode, source, link_target in entries:
                info = zipfile.ZipInfo(arcname, date_time=_ZIP_EPOCH)
                info.external_attr = ((stat.S_IFMT(mode) | (mode & 0o777)) & 0xFFFF) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                if link_target is not None:
                    archive.writestr(info, link_target)
                elif source is None:
                    archive.writestr(info, b"")
                else:
                    try:
                        with open(source, "rb") as reader, archive.open(
                            info, "w"
                        ) as writer:
                            shutil.copyfileobj(reader, writer, length=1 << 20)
                    except OSError as exc:
                        raise IPAError(
                            f"could not read {source} while repacking: {exc}"
                        ) from exc
        os.replace(temp_path, output_path)
    except BaseException:
        temp_path.unlink(missing_ok=True)
        raise
    return output_path


def _collect_archive_entries(
    work_dir: Path,
    entries: list[tuple[str, int, Path | None, str | None]],
) -> None:
    """(arcname, unix mode, file data, symlink target) for the whole tree."""
    for dirpath, dirnames, filenames in os.walk(work_dir):
        dirnames.sort()
        current = Path(dirpath)
        relative = current.relative_to(work_dir)
        prefix = relative.as_posix() + "/" if relative.parts else ""
        for name in dirnames:
            child = current / name
            arcname = prefix + name
            if _is_junk(arcname):
                continue
            if child.is_symlink():
                entries.append(
                    (arcname, stat.S_IFLNK | 0o777, None, os.readlink(child))
                )
                continue
            permissions = stat.S_IMODE(child.stat().st_mode) & 0o777 or 0o755
            entries.append((arcname + "/", stat.S_IFDIR | permissions, None, None))
        for name in filenames:
            child = current / name
            arcname = prefix + name
            if _is_junk(arcname):
                continue
            if child.is_symlink():
                entries.append(
                    (arcname, stat.S_IFLNK | 0o777, None, os.readlink(child))
                )
                continue
            try:
                mode = child.stat().st_mode
            except OSError as exc:
                raise IPAError(
                    f"could not read {child} while repacking: {exc}"
                ) from exc
            entries.append((arcname, mode, child, None))


def _is_junk(arcname: str) -> bool:
    """True for entries that must never land in a repacked IPA."""
    if arcname == ".DS_Store" or arcname.endswith("/.DS_Store"):
        return True
    return _JUNK_DIR in arcname.split("/")
