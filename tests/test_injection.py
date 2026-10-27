"""Offline tests for dylib and .deb tweak injection.

No Apple, no device, no network. Fixtures are built with the local
clang (one tiny arm64 executable, one arm64 dylib) and the system ar
and tar (synthetic Debian packages). Load commands are verified with
otool when available and LIEF otherwise, and tests skip cleanly when
clang, ar, or the other host tools are missing.
"""

from __future__ import annotations

import gzip
import io
import lzma
import os
import plistlib
import shutil
import stat
import subprocess
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from sideload import errors
from sideload.signing import injection, ipa

CLANG = shutil.which("clang")
OTOOL = shutil.which("otool")
AR = shutil.which("ar")
LIPO = shutil.which("lipo")
CODESIGN = shutil.which("codesign")
XZ = shutil.which("xz")

BUNDLE_ID = "com.example.inject"
APP_DIR = "Payload/Inject.app"
TWEAK_DIR = "Library/MobileSubstrate/DynamicLibraries"
_AR_MAGIC = b"!<arch>\n"
_TAR = shutil.which("tar") or "/usr/bin/tar"


def _run(command: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(command, check=False, capture_output=True)


def _clang_build(directory: Path, name: str, *archs: str, dynamic: bool = False) -> Path:
    """Build one small Mach-O with clang into directory."""
    source = directory / f"{name}.c"
    source.write_text(
        "int sideload_fixture_entry(void) { return 42; }\n"
        "int main(void) { return 0; }\n"
    )
    built = directory / name
    command = [str(CLANG)]
    for arch in archs:
        command += ["-arch", arch]
    if dynamic:
        command.append("-dynamiclib")
    command += ["-o", str(built), str(source)]
    result = _run(command)
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
    return built


def _info_plist(bundle_id: str, executable: str) -> bytes:
    return plistlib.dumps(
        {
            "CFBundleIdentifier": bundle_id,
            "CFBundleExecutable": executable,
            "CFBundleName": bundle_id.rsplit(".", 1)[-1],
            "CFBundleVersion": "1.0",
        }
    )


def _make_ipa(app_dir: Path, output: Path) -> Path:
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for dirpath, _dirnames, filenames in os.walk(app_dir):
            for name in sorted(filenames):
                child = Path(dirpath) / name
                info = zipfile.ZipInfo(
                    f"{APP_DIR}/{child.relative_to(app_dir).as_posix()}",
                    date_time=(2025, 1, 1, 0, 0, 0),
                )
                info.external_attr = (stat.S_IFREG | 0o755) << 16
                archive.writestr(info, child.read_bytes())
    return output


def _extract(tmp_path: Path, ipa_path: Path) -> ipa.IPABundle:
    return ipa.extract_ipa(ipa_path, dest_dir=tmp_path / "work")


def _load_names(executable: Path) -> list[str]:
    """Every dylib install name, via otool when available else LIEF."""
    if OTOOL is not None:
        result = _run([OTOOL, "-L", str(executable)])
        assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
        lines = result.stdout.decode("utf-8", "replace").splitlines()[1:]
        return [line.split(" (compatibility")[0].strip() for line in lines if line.strip()]
    import lief

    fat = lief.MachO.parse(str(executable))
    assert fat is not None
    names: list[str] = []
    for index in range(len(fat)):
        binary = fat.at(index)
        if binary is not None:
            names.extend(command.name for command in binary.libraries)
    return names


def _slice_load_names(executable: Path, arch: str) -> list[str]:
    """Install names of one slice of a universal binary, via otool."""
    assert OTOOL is not None
    result = _run([OTOOL, "-arch", arch, "-L", str(executable)])
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
    lines = result.stdout.decode("utf-8", "replace").splitlines()[1:]
    return [line.split(" (compatibility")[0].strip() for line in lines if line.strip()]


# ------------------------------------------------------------- fixtures


@pytest.fixture(scope="session")
def fixture_root(tmp_path_factory: pytest.TempPathFactory) -> SimpleNamespace:
    """One tiny arm64 app IPA plus arm64, universal, and x86_64 dylibs."""
    if CLANG is None:
        pytest.skip("clang not found")
    root = tmp_path_factory.mktemp("sideload-inject-test")
    app = root / "Payload" / "Inject.app"
    app.mkdir(parents=True)
    (app / "Info.plist").write_bytes(_info_plist(BUNDLE_ID, "Inject"))
    _clang_build(root, "Inject").rename(app / "Inject")
    os.chmod(app / "Inject", 0o755)
    return SimpleNamespace(
        root=root,
        app=app,
        ipa=_make_ipa(app, root / "inject.ipa"),
        dylib=_clang_build(root, "libtweak.dylib", "arm64", dynamic=True),
        fat_dylib=_clang_build(root, "libfat.dylib", "arm64", "x86_64", dynamic=True),
        x86_dylib=_clang_build(root, "libx86only.dylib", "x86_64", dynamic=True),
    )


def _tar_tree(source: Path, output: Path, *flags: str) -> None:
    """tar the Library tree into a .tar archive."""
    environment = {**os.environ, "COPYFILE_DISABLE": "1"}
    result = subprocess.run(
        [_TAR, "--format=ustar", *flags, "-cf", str(output), "Library"],
        cwd=source,
        env=environment,
        check=False,
        capture_output=True,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")


def _make_deb(output: Path, debian_binary: Path, control: Path, data_tar: Path) -> Path:
    """One synthetic .deb with the system ar.

    -S suppresses the symbol index: with it, macOS ar rewrites the
    archive down to the armap and silently drops the members.
    """
    result = _run([AR, "-r", "-S", str(output), str(debian_binary), str(control), str(data_tar)])
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
    return output


@pytest.fixture(scope="session")
def fixture_debs(
    tmp_path_factory: pytest.TempPathFactory, fixture_root: SimpleNamespace
) -> SimpleNamespace:
    """Synthetic Debian packages in every supported data.tar flavor."""
    if AR is None:
        pytest.skip("ar not found")
    root = tmp_path_factory.mktemp("sideload-inject-deb-test")

    def tweak_tree(name: str, bundles: list[str] | None, classes: list[str] | None) -> Path:
        tree = root / f"{name}-tree"
        tweak = tree / TWEAK_DIR
        tweak.mkdir(parents=True)
        shutil.copyfile(fixture_root.dylib, tweak / "libdeb.dylib")
        os.chmod(tweak / "libdeb.dylib", 0o755)
        if bundles is not None or classes is not None:
            filt: dict[str, object] = {}
            if bundles is not None:
                filt["Bundles"] = bundles
            if classes is not None:
                filt["Classes"] = classes
            (tweak / "libdeb.plist").write_bytes(
                plistlib.dumps({"Filter": filt} if filt else {})
            )
        return tree

    debian_binary = root / "debian-binary"
    debian_binary.write_bytes(b"2.0\n")
    control = root / "control.tar.gz"
    control.write_bytes(b"placeholder-control-archive")

    def variant(name: str, tree: Path, data_tar: Path) -> Path:
        return _make_deb(root / f"{name}.deb", debian_binary, control, data_tar)

    matching_tree = tweak_tree("matching", [BUNDLE_ID], None)
    gz = root / "data.tar.gz"
    _tar_tree(matching_tree, gz, "-z")
    xz = root / "data.tar.xz"
    _tar_tree(matching_tree, xz, "-J")
    plain = root / "data.tar"
    _tar_tree(matching_tree, plain)

    lzma_tar = root / "data.tar.lzma"
    if XZ is not None:
        with plain.open("rb") as handle:
            result = subprocess.run(
                [XZ, "--format=lzma", "-c", "-"],
                input=handle.read(),
                check=False,
                capture_output=True,
            )
        lzma_tar.write_bytes(result.stdout)

    def deb_from(tree_name: str, bundles: list[str] | None, classes: list[str] | None) -> Path:
        tree = tweak_tree(tree_name, bundles, classes)
        data_dir = root / f"{tree_name}-data"
        data_dir.mkdir(parents=True, exist_ok=True)
        data_tar = data_dir / "data.tar.gz"
        _tar_tree(tree, data_tar, "-z")
        return _make_deb(root / f"{tree_name}.deb", debian_binary, control, data_tar)

    return SimpleNamespace(
        root=root,
        matching=variant("matching", matching_tree, gz),
        xz=variant("xz", matching_tree, xz),
        lzma=variant("lzma", matching_tree, lzma_tar) if lzma_tar.is_file() else None,
        plain=variant("plain", matching_tree, plain),
        mismatch=deb_from("mismatch", ["com.other.app"], None),
        no_filter=deb_from("bare", None, None),
        classes_only=deb_from("classesonly", None, ["SpringBoard"]),
    )


# ------------------------------------------------------------- dylib


def test_inject_dylib_copies_into_frameworks_and_links(
    tmp_path: Path, fixture_root: SimpleNamespace
) -> None:
    bundle = _extract(tmp_path, fixture_root.ipa)
    messages: list[str] = []
    destination = injection.inject_dylib(
        bundle.main_bundle, fixture_root.dylib, notify=messages.append
    )
    assert destination == bundle.main_bundle.root / "Frameworks" / "libtweak.dylib"
    assert destination.is_file()
    assert os.access(destination, os.X_OK)
    install_name = injection.install_name_for("libtweak.dylib")
    assert install_name in _load_names(bundle.main_bundle.executable)
    assert any("libtweak.dylib -> Frameworks/libtweak.dylib" in m for m in messages)


def test_injected_dylib_is_signed_before_the_executable(
    tmp_path: Path, fixture_root: SimpleNamespace
) -> None:
    bundle = _extract(tmp_path, fixture_root.ipa)
    injection.inject_dylib(
        bundle.main_bundle, fixture_root.dylib, notify=lambda _m: None
    )
    inventory = bundle.main_bundle.signable_inventory()
    names = [path.name for path in inventory]
    assert "libtweak.dylib" in names
    assert names.index("libtweak.dylib") < names.index(
        bundle.main_bundle.executable.name
    )
    copied = bundle.main_bundle.root / "Frameworks" / "libtweak.dylib"
    assert copied.is_file() and not copied.is_symlink()


def test_duplicate_injection_is_idempotent(
    tmp_path: Path, fixture_root: SimpleNamespace
) -> None:
    bundle = _extract(tmp_path, fixture_root.ipa)
    injection.inject_dylib(
        bundle.main_bundle, fixture_root.dylib, notify=lambda _m: None
    )
    messages: list[str] = []
    injection.inject_dylib(bundle.main_bundle, fixture_root.dylib, notify=messages.append)
    install_name = injection.install_name_for("libtweak.dylib")
    names = _load_names(bundle.main_bundle.executable)
    assert names.count(install_name) == 1
    assert any("already linked" in m for m in messages)


def test_apply_injections_is_idempotent_across_repeats(
    tmp_path: Path, fixture_root: SimpleNamespace
) -> None:
    bundle = _extract(tmp_path, fixture_root.ipa)
    injected = injection.apply_injections(
        bundle,
        [fixture_root.dylib, fixture_root.dylib],
        [],
        notify=lambda _m: None,
    )
    assert injected == [
        bundle.main_bundle.root / "Frameworks" / "libtweak.dylib",
        bundle.main_bundle.root / "Frameworks" / "libtweak.dylib",
    ]
    names = _load_names(bundle.main_bundle.executable)
    assert names.count(injection.install_name_for("libtweak.dylib")) == 1


def test_inject_rejects_missing_file(tmp_path: Path) -> None:
    app = tmp_path / "Payload" / "Demo.app"
    app.mkdir(parents=True)
    (app / "Info.plist").write_bytes(_info_plist(BUNDLE_ID, "Demo"))
    (app / "Demo").write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 28)
    bundle = ipa.IPABundle(
        ipa_path=tmp_path / "x.ipa",
        work_dir=tmp_path,
        main_bundle=ipa.AppBundle(
            root=app,
            bundle_identifier=BUNDLE_ID,
            executable=app / "Demo",
            info_plist_path=app / "Info.plist",
        ),
    )
    with pytest.raises(errors.IPAError, match="not found"):
        injection.inject_dylib(bundle.main_bundle, tmp_path / "missing.dylib")


def test_inject_rejects_non_macho(
    tmp_path: Path, fixture_root: SimpleNamespace
) -> None:
    bundle = _extract(tmp_path, fixture_root.ipa)
    text = tmp_path / "notalib.dylib"
    text.write_text("plain text, not a binary")
    with pytest.raises(errors.IPAError, match="not a Mach-O dylib"):
        injection.inject_dylib(bundle.main_bundle, text)


def test_inject_rejects_unsupported_architecture(
    tmp_path: Path, fixture_root: SimpleNamespace
) -> None:
    bundle = _extract(tmp_path, fixture_root.ipa)
    with pytest.raises(errors.UnsupportedIPAError) as excinfo:
        injection.inject_dylib(bundle.main_bundle, fixture_root.x86_dylib)
    assert "x86_64" in excinfo.value.message
    assert "arm64" in (excinfo.value.hint or "")


@pytest.mark.skipif(LIPO is None, reason="lipo not found")
def test_inject_accepts_universal_binaries(
    tmp_path: Path, fixture_root: SimpleNamespace
) -> None:
    fat_exe = _clang_build(fixture_root.root, "FatInject", "arm64", "x86_64")
    fat_app = fixture_root.root / "Payload" / "FatInject.app"
    fat_app.mkdir(parents=True, exist_ok=True)
    (fat_app / "Info.plist").write_bytes(_info_plist(BUNDLE_ID, "FatInject"))
    shutil.copyfile(fat_exe, fat_app / "FatInject")
    os.chmod(fat_app / "FatInject", 0o755)
    fat_ipa = _make_ipa(fat_app, fixture_root.root / "fat.ipa")
    bundle = _extract(tmp_path, fat_ipa)
    injection.inject_dylib(
        bundle.main_bundle, fixture_root.fat_dylib, notify=lambda _m: None
    )
    install_name = injection.install_name_for("libfat.dylib")
    assert install_name in _slice_load_names(bundle.main_bundle.executable, "arm64")
    assert install_name in _slice_load_names(bundle.main_bundle.executable, "x86_64")


@pytest.mark.skipif(CODESIGN is None, reason="codesign not found")
def test_injected_executable_can_be_re_signed(
    tmp_path: Path, fixture_root: SimpleNamespace
) -> None:
    bundle = _extract(tmp_path, fixture_root.ipa)
    injection.inject_dylib(
        bundle.main_bundle, fixture_root.dylib, notify=lambda _m: None
    )
    executable = bundle.main_bundle.executable
    sign = _run([CODESIGN, "--force", "--sign", "-", str(executable)])
    assert sign.returncode == 0, sign.stderr.decode("utf-8", "replace")
    verify = _run([CODESIGN, "--verify", "--verbose=2", str(executable)])
    assert verify.returncode == 0, verify.stderr.decode("utf-8", "replace")


# ------------------------------------------------------------- .deb


def test_deb_gz_injection_end_to_end(
    tmp_path: Path, fixture_root: SimpleNamespace, fixture_debs: SimpleNamespace
) -> None:
    bundle = _extract(tmp_path, fixture_root.ipa)
    messages: list[str] = []
    injected = injection.inject_deb(
        bundle.main_bundle, fixture_debs.matching, [BUNDLE_ID], notify=messages.append
    )
    assert injected == [bundle.main_bundle.root / "Frameworks" / "libdeb.dylib"]
    assert any("matches bundle id" in m for m in messages)
    assert injection.install_name_for("libdeb.dylib") in _load_names(
        bundle.main_bundle.executable
    )


def test_deb_xz_lzma_and_plain_flavors(
    tmp_path: Path, fixture_root: SimpleNamespace, fixture_debs: SimpleNamespace
) -> None:
    flavors = [fixture_debs.xz, fixture_debs.plain]
    if fixture_debs.lzma is not None:
        flavors.append(fixture_debs.lzma)
    assert len(flavors) >= 2
    for deb in flavors:
        bundle = _extract(tmp_path / deb.stem, fixture_root.ipa)
        injected = injection.inject_deb(
            bundle.main_bundle, deb, [BUNDLE_ID], notify=lambda _m: None
        )
        assert injected, f"nothing injected from {deb.name}"
        assert injection.install_name_for("libdeb.dylib") in _load_names(
            bundle.main_bundle.executable
        )


def test_deb_filter_mismatch_skips_the_dylib(
    tmp_path: Path, fixture_root: SimpleNamespace, fixture_debs: SimpleNamespace
) -> None:
    bundle = _extract(tmp_path, fixture_root.ipa)
    messages: list[str] = []
    injected = injection.inject_deb(
        bundle.main_bundle, fixture_debs.mismatch, [BUNDLE_ID], notify=messages.append
    )
    assert injected == []
    assert any("does not match" in m for m in messages)
    assert not (bundle.main_bundle.root / "Frameworks" / "libdeb.dylib").exists()


def test_deb_without_plist_injects_without_filter_output(
    tmp_path: Path, fixture_root: SimpleNamespace, fixture_debs: SimpleNamespace
) -> None:
    bundle = _extract(tmp_path, fixture_root.ipa)
    messages: list[str] = []
    injected = injection.inject_deb(
        bundle.main_bundle, fixture_debs.no_filter, [BUNDLE_ID], notify=messages.append
    )
    assert injected == [bundle.main_bundle.root / "Frameworks" / "libdeb.dylib"]
    assert not any("filter" in m for m in messages)


def test_deb_classes_only_filter_warns_and_injects(
    tmp_path: Path, fixture_root: SimpleNamespace, fixture_debs: SimpleNamespace
) -> None:
    bundle = _extract(tmp_path, fixture_root.ipa)
    messages: list[str] = []
    injected = injection.inject_deb(
        bundle.main_bundle, fixture_debs.classes_only, [BUNDLE_ID], notify=messages.append
    )
    assert injected == [bundle.main_bundle.root / "Frameworks" / "libdeb.dylib"]
    assert any("filter is ignored" in m for m in messages)


def test_deb_rejects_non_ar_archive(
    tmp_path: Path, fixture_root: SimpleNamespace
) -> None:
    fake = tmp_path / "tweak.deb"
    fake.write_bytes(b"not an ar archive at all")
    bundle = _extract(tmp_path, fixture_root.ipa)
    with pytest.raises(errors.IPAError, match="ar archive header"):
        injection.inject_deb(bundle.main_bundle, fake, [BUNDLE_ID])


def test_deb_rejects_missing_file(
    tmp_path: Path, fixture_root: SimpleNamespace
) -> None:
    bundle = _extract(tmp_path, fixture_root.ipa)
    with pytest.raises(errors.IPAError, match="not found"):
        injection.inject_deb(
            bundle.main_bundle, tmp_path / "missing.deb", [BUNDLE_ID]
        )


def test_deb_rejects_archive_without_data_tar(
    tmp_path: Path, fixture_debs: SimpleNamespace
) -> None:
    deb = tmp_path / "control-only.deb"
    _make_deb(
        deb,
        fixture_debs.root / "debian-binary",
        fixture_debs.root / "control.tar.gz",
        fixture_debs.root / "control.tar.gz",
    )
    with pytest.raises(errors.IPAError, match="no data.tar member"):
        injection.inject_deb(
            ipa.AppBundle(
                root=Path("/nope"),
                bundle_identifier=BUNDLE_ID,
                executable=Path("/nope/x"),
                info_plist_path=Path("/nope/Info.plist"),
            ),
            deb,
            [BUNDLE_ID],
        )


def _hand_ar_members(members: list[tuple[str, bytes]]) -> bytes:
    """Build one ar archive by hand, GNU or BSD style member names."""

    def member(name: str, data: bytes) -> bytes:
        header = name.ljust(16).encode("ascii")
        size = str(len(data)).encode("ascii")
        header += b"0".ljust(12) + b"0".ljust(6) + b"0".ljust(6) + b"100644".ljust(8)
        header += size.ljust(10) + b"`\n"
        pad = b"\n" if len(data) % 2 else b""
        return header + data + pad

    payload = _AR_MAGIC
    for name, data in members:
        payload += member(name, data)
    return payload


def test_deb_rejects_unsupported_zstd_flavor(
    tmp_path: Path, fixture_root: SimpleNamespace
) -> None:
    deb = tmp_path / "zstd.deb"
    deb.write_bytes(
        _hand_ar_members(
            [
                ("debian-binary", b"2.0\n"),
                ("control.tar.gz", b"placeholder"),
                ("data.tar.zst", b"placeholder"),
            ]
        )
    )
    bundle = _extract(tmp_path, fixture_root.ipa)
    with pytest.raises(errors.UnsupportedIPAError, match="data.tar.zst"):
        injection.inject_deb(bundle.main_bundle, deb, [BUNDLE_ID])


def test_deb_gnu_format_with_long_names(
    tmp_path: Path, fixture_root: SimpleNamespace
) -> None:
    """A GNU ar archive (string table, /offset names, and trailing
    slash inline names) is parsed and injected."""
    tar_bytes = _tweak_tar_bytes(fixture_root.dylib.read_bytes(), with_plist=False)
    data_xz = lzma.compress(tar_bytes, format=lzma.FORMAT_XZ)
    long_control = "a-control-name-longer-than-fifteen-chars.tar.gz"
    string_table = (long_control + "/\n").encode("utf-8")

    def gnu_member(name_field: str, data: bytes) -> bytes:
        header = name_field.ljust(16).encode("ascii")
        size = str(len(data)).encode("ascii")
        header += b"0".ljust(12) + b"0".ljust(6) + b"0".ljust(6) + b"100644".ljust(8)
        header += size.ljust(10) + b"`\n"
        pad = b"\n" if len(data) % 2 else b""
        return header + data + pad

    payload = _AR_MAGIC
    payload += gnu_member("/", b"")  # GNU armap, must be skipped
    payload += gnu_member("//", string_table)
    payload += gnu_member("debian-binary/", b"2.0\n")
    payload += gnu_member("control.tar.gz/", b"placeholder")
    payload += gnu_member("/0", b"placeholder long control member")
    payload += gnu_member("data.tar.xz/", data_xz)
    deb = tmp_path / "gnu.deb"
    deb.write_bytes(payload)
    names = [member.name for member in injection._iter_ar_members(deb)]
    assert names == ["/", "//", "debian-binary", "control.tar.gz", long_control, "data.tar.xz"]

    bundle = _extract(tmp_path, fixture_root.ipa)
    injected = injection.inject_deb(
        bundle.main_bundle, deb, [BUNDLE_ID], notify=lambda _m: None
    )
    assert injected == [bundle.main_bundle.root / "Frameworks" / "libtweak.dylib"]
    assert injection.install_name_for("libtweak.dylib") in _load_names(
        bundle.main_bundle.executable
    )


def _tweak_tar_bytes(dylib: bytes, with_plist: bool) -> bytes:
    """A ustar tar archive holding the MobileSubstrate layout."""

    def header(name: str, size: int) -> bytes:
        block = bytearray(512)
        block[0 : len(name)] = name[:100].encode("utf-8")
        block[100:108] = b"0000755\x00"
        block[108:116] = b"0000000\x00"
        block[116:124] = b"0000000\x00"
        block[124:136] = f"{size:011o}".encode("ascii").ljust(12, b"\x00")
        block[136:148] = b"00000000000\x00"
        block[156:157] = b"0"
        block[257:265] = b"ustar\x0000"
        block[148:156] = b"        "
        checksum = sum(block)
        block[148:156] = f"{checksum:06o}\x00 ".encode("ascii")
        return bytes(block)

    def entry(name: str, data: bytes) -> bytes:
        pad = (-len(data)) % 512
        return header(name, len(data)) + data + b"\x00" * pad

    payload = b""
    payload += entry("./Library", b"")
    payload += entry("./Library/MobileSubstrate", b"")
    payload += entry(f"./{TWEAK_DIR}", b"")
    payload += entry(f"./{TWEAK_DIR}/libtweak.dylib", dylib)
    if with_plist:
        payload += entry(
            f"./{TWEAK_DIR}/libtweak.plist",
            plistlib.dumps({"Filter": {"Bundles": [BUNDLE_ID]}}),
        )
    return payload + b"\x00" * 1024


def test_deb_truncated_data_tar_fails_clearly(
    tmp_path: Path, fixture_root: SimpleNamespace
) -> None:
    """A data.tar that ends mid member surfaces as an IPAError."""
    tar_bytes = _tweak_tar_bytes(fixture_root.dylib.read_bytes(), with_plist=True)
    truncated = tar_bytes[: 512 * 6]  # cut inside the dylib member data
    deb = tmp_path / "truncated.deb"
    deb.write_bytes(
        _hand_ar_members(
            [
                ("debian-binary", b"2.0\n"),
                ("control.tar.gz", b"placeholder"),
                ("data.tar", truncated),
            ]
        )
    )
    bundle = _extract(tmp_path, fixture_root.ipa)
    with pytest.raises(errors.IPAError, match="malformed"):
        injection.inject_deb(bundle.main_bundle, deb, [BUNDLE_ID])


def test_bounded_reader_enforces_the_cap() -> None:
    reader = injection._BoundedReader(io.BytesIO(b"abcdef"), 4)
    assert reader.read(3) == b"abc"
    with pytest.raises(OSError):
        reader.read(2)


# ------------------------------------------------------- parser surface


def test_apply_injections_with_no_requests_is_a_no_op(
    tmp_path: Path, fixture_root: SimpleNamespace
) -> None:
    bundle = _extract(tmp_path, fixture_root.ipa)

    def snapshot() -> list[str]:
        return sorted(
            str(path.relative_to(bundle.main_bundle.root))
            for path in bundle.main_bundle.root.rglob("*")
        )

    before = snapshot()
    injected = injection.apply_injections(bundle, [], [], notify=lambda _m: None)
    assert injected == []
    assert snapshot() == before


def test_apply_injections_combines_dylibs_and_debs(
    tmp_path: Path,
    fixture_root: SimpleNamespace,
    fixture_debs: SimpleNamespace,
) -> None:
    bundle = _extract(tmp_path, fixture_root.ipa)
    assert [b.bundle_identifier for b in bundle.all_bundles] == [BUNDLE_ID]
    injected = injection.apply_injections(
        bundle,
        [fixture_root.dylib],
        [fixture_debs.matching],
        notify=lambda _m: None,
    )
    assert {path.name for path in injected} == {"libtweak.dylib", "libdeb.dylib"}
    loaded = _load_names(bundle.main_bundle.executable)
    assert injection.install_name_for("libtweak.dylib") in loaded
    assert injection.install_name_for("libdeb.dylib") in loaded


def test_iter_tweak_names_rejects_unsafe_entries() -> None:
    safe = injection._tweak_relative_name(
        "./Library/MobileSubstrate/DynamicLibraries/a.dylib"
    )
    assert safe == "Library/MobileSubstrate/DynamicLibraries/a.dylib"
    assert injection._tweak_relative_name("/etc/passwd") is None
    assert injection._tweak_relative_name("../outside.dylib") is None
    assert injection._tweak_relative_name("Library\\escape.dylib") is None


def test_gzip_data_tar_from_slice_reader(
    tmp_path: Path, fixture_root: SimpleNamespace
) -> None:
    """A gz data.tar built by tar is read through the bounded stack."""
    tar_bytes = _tweak_tar_bytes(fixture_root.dylib.read_bytes(), with_plist=False)
    gz_bytes = gzip.compress(tar_bytes)
    deb = tmp_path / "gz-hand.deb"
    deb.write_bytes(
        _hand_ar_members(
            [
                ("debian-binary", b"2.0\n"),
                ("control.tar.gz", b"placeholder"),
                ("data.tar.gz", gz_bytes),
            ]
        )
    )
    bundle = _extract(tmp_path, fixture_root.ipa)
    injected = injection.inject_deb(
        bundle.main_bundle, deb, [BUNDLE_ID], notify=lambda _m: None
    )
    assert injected == [bundle.main_bundle.root / "Frameworks" / "libtweak.dylib"]