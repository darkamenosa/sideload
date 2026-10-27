"""Offline tests for signing/customize.py (Sideloadly-style tweaks).

Reuses the fixture app from test_signing.py (nested framework, loose
dylib, appex extension). No Apple, no device, no network; the only
external tool exercised is the macOS sips binary, and every test that
needs it skips when sips is absent.
"""

from __future__ import annotations

import plistlib
import shutil
import struct
import zipfile
import zlib
from pathlib import Path

import pytest
from test_signing import fixture_ipa, make_profile

from sideload import errors
from sideload.signing import customize, entitlements, ipa

# fixture_ipa is re-exported so pytest resolves the shared session
# fixture (built in test_signing.py) for the tests in this module.
__all__ = ["fixture_ipa"]

SIPS = shutil.which("sips")
require_sips = pytest.mark.skipif(SIPS is None, reason="sips not found")


@pytest.fixture()
def extracted(tmp_path: Path, request: pytest.FixtureRequest) -> ipa.IPABundle:
    """A fresh extraction of the shared fixture app."""
    shared = request.getfixturevalue("fixture_ipa")
    return ipa.extract_ipa(shared.ipa, dest_dir=tmp_path / "work")


def _info(bundle: ipa.AppBundle) -> dict[str, object]:
    return plistlib.loads(bundle.info_plist_path.read_bytes())


def _write_png(path: Path, edge: int, color: tuple[int, int, int] = (255, 0, 0)) -> None:
    """A minimal solid RGB PNG built with the stdlib only."""
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = b"".join(b"\x00" + bytes(color) * edge for _ in range(edge))

    def chunk(tag: bytes, payload: bytes) -> bytes:
        body = tag + payload
        return struct.pack(">I", len(payload)) + body + struct.pack(
            ">I", zlib.crc32(body) & 0xFFFFFFFF
        )

    header = struct.pack(">IIBBBBB", edge, edge, 8, 2, 0, 0, 0)
    path.write_bytes(
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )


def _pixel_width(path: Path) -> int:
    assert SIPS is not None
    measured = customize._sips_dimensions(SIPS, path)
    assert measured is not None, f"sips could not measure {path}"
    return measured[0]


def _bare_app(tmp_path: Path) -> ipa.AppBundle:
    """A minimal on-disk bundle with no PlugIns directory."""
    root = tmp_path / "Bare.app"
    root.mkdir()
    info = root / "Info.plist"
    info.write_bytes(
        plistlib.dumps(
            {"CFBundleIdentifier": "com.example.bare", "CFBundleExecutable": "Bare"}
        )
    )
    executable = root / "Bare"
    executable.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 28)
    return ipa.AppBundle(
        root=root,
        bundle_identifier="com.example.bare",
        executable=executable,
        info_plist_path=info,
    )


# --------------------------------------------------------- display name


def test_set_display_name_sets_both_keys(extracted):
    bundle = extracted.main_bundle
    customize.set_display_name(bundle, "Nightly Pro")
    values = _info(bundle)
    assert values["CFBundleDisplayName"] == "Nightly Pro"
    assert values["CFBundleName"] == "Nightly Pro"
    # the fixture ships an XML plist and it stays XML
    assert bundle.info_plist_path.read_bytes().startswith(b"<?xml")


def test_plist_edits_preserve_the_binary_plist_format(extracted):
    bundle = extracted.main_bundle
    bundle.info_plist_path.write_bytes(
        plistlib.dumps(_info(bundle), fmt=plistlib.FMT_BINARY)
    )
    customize.set_display_name(bundle, "Beta Build")
    raw = bundle.info_plist_path.read_bytes()
    assert raw.startswith(b"bplist00")
    assert plistlib.loads(raw)["CFBundleDisplayName"] == "Beta Build"


def test_set_display_name_rejects_empty_name(extracted):
    with pytest.raises(errors.UsageError):
        customize.set_display_name(extracted.main_bundle, "")


# --------------------------------------------------------- minimum os


def test_set_minimum_os_version_sets_minimumosversion(extracted):
    bundle = extracted.main_bundle
    customize.set_minimum_os_version(bundle, "13.0")
    values = _info(bundle)
    assert values["MinimumOSVersion"] == "13.0"
    # DeploymentTarget is only rewritten when present, never added
    assert "DeploymentTarget" not in values


def test_set_minimum_os_version_updates_deployment_target_when_present(extracted):
    bundle = extracted.main_bundle
    values = _info(bundle)
    values["DeploymentTarget"] = "12.0"
    bundle.info_plist_path.write_bytes(plistlib.dumps(values))
    customize.set_minimum_os_version(bundle, "14.1")
    values = _info(bundle)
    assert values["MinimumOSVersion"] == "14.1"
    assert values["DeploymentTarget"] == "14.1"


def test_set_minimum_os_version_rejects_malformed_version(extracted):
    with pytest.raises(errors.UsageError):
        customize.set_minimum_os_version(extracted.main_bundle, "ios13")


def test_is_valid_os_version():
    assert customize.is_valid_os_version("13")
    assert customize.is_valid_os_version("13.0")
    assert customize.is_valid_os_version("13.4.1")
    assert not customize.is_valid_os_version("13.0.1.2.3")
    assert not customize.is_valid_os_version("iOS 13")
    assert not customize.is_valid_os_version("")


# ---------------------------------------------------- supported devices


def test_set_supported_devices_replaces_the_existing_list(extracted):
    bundle = extracted.main_bundle
    values = _info(bundle)
    values["UISupportedDevices"] = ["iPhone8,1"]
    bundle.info_plist_path.write_bytes(plistlib.dumps(values))
    customize.set_supported_devices(bundle, ["iPhone12,3", "iPad13,2"])
    assert _info(bundle)["UISupportedDevices"] == ["iPhone12,3", "iPad13,2"]


def test_set_supported_devices_rejects_an_empty_list(extracted):
    with pytest.raises(errors.UsageError):
        customize.set_supported_devices(extracted.main_bundle, ["  "])


# ------------------------------------------------------ plugin removal


def test_remove_plugins_deletes_appex_and_watch_content(extracted):
    bundle = extracted.main_bundle
    watch = bundle.root / "Watch" / "Wrist.app"
    watch.mkdir(parents=True)
    (watch / "placeholder").write_bytes(b"x")
    removed = customize.remove_plugins(bundle)
    assert removed == ["FixExt.appex", "Watch"]
    assert not (bundle.root / "PlugIns").exists()
    assert not (bundle.root / "Watch").exists()
    # the framework and the loose dylib are untouched
    assert (bundle.root / "Frameworks" / "FixKit.framework" / "FixKit").is_file()
    assert (bundle.root / "Libraries" / "libfix.dylib").is_file()
    # and a second run is a no-op
    assert customize.remove_plugins(bundle) == []


def test_remove_plugins_without_a_plugins_dir_returns_empty(tmp_path):
    bundle = _bare_app(tmp_path)
    assert customize.remove_plugins(bundle) == []
    assert bundle.root.is_dir()


def test_apply_customization_remove_plugins_recomputes_the_inventory(
    extracted: ipa.IPABundle, tmp_path: Path
):
    bundle = extracted
    assert [b.root.name for b in bundle.all_bundles] == [
        "Fixture.app",
        "FixKit.framework",
        "FixExt.appex",
    ]
    notes = customize.apply_customization(
        bundle, customize.AppCustomization(remove_plugins=True)
    )
    assert notes == ["removed extension: FixExt.appex"]
    # the recomputed inventory drives App IDs, profiles, entitlements,
    # and signing: the extension is gone from all of them
    assert [b.root.name for b in bundle.all_bundles] == [
        "Fixture.app",
        "FixKit.framework",
    ]
    inventory = [
        path.relative_to(bundle.main_bundle.root).as_posix()
        for path in bundle.main_bundle.signable_inventory()
    ]
    assert inventory == [
        "Libraries/libfix.dylib",
        "Frameworks/FixKit.framework/FixKit",
        "Fixture",
    ]
    # the output IPA contains no PlugIns content at all
    out = tmp_path / "out.ipa"
    ipa.repack_ipa(bundle, out)
    with zipfile.ZipFile(out) as archive:
        names = archive.namelist()
    assert not any("PlugIns" in name for name in names)
    assert any(name.endswith("FixKit.framework/FixKit") for name in names)


def test_apply_customization_without_flags_is_a_noop(extracted: ipa.IPABundle):
    bundle = extracted
    info_before = bundle.main_bundle.info_plist_path.read_bytes()
    notes = customize.apply_customization(bundle, customize.AppCustomization())
    assert notes == []
    assert bundle.main_bundle.info_plist_path.read_bytes() == info_before
    assert [b.root.name for b in bundle.all_bundles] == [
        "Fixture.app",
        "FixKit.framework",
        "FixExt.appex",
    ]


# ------------------------------------------------- custom entitlements


def test_load_entitlements_reads_xml_and_binary_plists(tmp_path):
    xml_path = tmp_path / "extra.plist"
    with open(xml_path, "wb") as handle:
        plistlib.dump({"com.apple.developer.aps-environment": "development"}, handle)
    binary_path = tmp_path / "extra.binary.plist"
    with open(binary_path, "wb") as handle:
        plistlib.dump({"get-task-allow": True}, handle, fmt=plistlib.FMT_BINARY)
    assert customize.load_entitlements(xml_path) == {
        "com.apple.developer.aps-environment": "development"
    }
    assert customize.load_entitlements(binary_path) == {"get-task-allow": True}


def test_load_entitlements_rejects_bad_input(tmp_path):
    with pytest.raises(errors.UsageError):
        customize.load_entitlements(tmp_path / "missing.plist")
    garbage = tmp_path / "garbage.plist"
    garbage.write_bytes(b"this is not a plist")
    with pytest.raises(errors.UsageError):
        customize.load_entitlements(garbage)
    array_path = tmp_path / "array.plist"
    array_path.write_bytes(plistlib.dumps(["not", "a", "dict"]))
    with pytest.raises(errors.UsageError):
        customize.load_entitlements(array_path)


def test_split_extra_entitlements_granted_and_dropped():
    profile = make_profile()
    requested = {
        "com.apple.developer.icloud-container-identifiers": ["iCloud.com.example"],
        "com.apple.private.hax": True,
    }
    granted, dropped = customize.split_extra_entitlements(profile, requested)
    assert granted == {
        "com.apple.developer.icloud-container-identifiers": ["iCloud.com.example"]
    }
    assert dropped == ["com.apple.private.hax"]
    # the granted half flows through build_entitlements' extra parameter
    merged, merged_dropped = entitlements.build_entitlements(
        profile, None, granted, strict=False
    )
    assert merged["com.apple.developer.icloud-container-identifiers"] == (
        ["iCloud.com.example"]
    )
    assert "com.apple.private.hax" not in merged
    assert merged_dropped == []


def test_split_extra_entitlements_managed_keys_stay_forced():
    """application-identifier and friends are granted by the profile, so
    they pass the split, but build_entitlements rewrites them from the
    profile regardless of what the user plist asked for."""
    profile = make_profile()
    requested = {"application-identifier": "OTHER.com.example.fixture"}
    granted, dropped = customize.split_extra_entitlements(profile, requested)
    assert granted == requested
    assert dropped == []
    merged, _ = entitlements.build_entitlements(profile, None, granted, strict=False)
    assert merged["application-identifier"] == "TEAM123.com.example.fixture.team123"


# ------------------------------------------------------ flag validation


def test_build_customization_accepts_and_normalizes_flags(tmp_path):
    entitlements_file = tmp_path / "extra.plist"
    entitlements_file.write_bytes(plistlib.dumps({"get-task-allow": True}))
    icon = tmp_path / "icon.png"
    icon.write_bytes(b"png-bytes")
    custom = customize.build_customization(
        name="Nightly",
        remove_plugins=True,
        entitlements_path=str(entitlements_file),
        min_os="13.0",
        supported_devices=["iPhone12,3", " iPad13,2 "],
        icon_path=str(icon),
    )
    assert custom.display_name == "Nightly"
    assert custom.remove_plugins is True
    assert custom.extra_entitlements == {"get-task-allow": True}
    assert custom.minimum_os_version == "13.0"
    assert custom.supported_devices == ("iPhone12,3", "iPad13,2")
    assert custom.icon_source == icon


def test_build_customization_rejects_bad_flags(tmp_path):
    def build(**flags: object) -> None:
        defaults: dict[str, object] = {
            "name": None,
            "remove_plugins": False,
            "entitlements_path": None,
            "min_os": None,
            "supported_devices": None,
            "icon_path": None,
        }
        defaults.update(flags)
        customize.build_customization(**defaults)

    with pytest.raises(errors.UsageError):
        build(name="")
    with pytest.raises(errors.UsageError):
        build(min_os="thirteen")
    with pytest.raises(errors.UsageError):
        build(supported_devices=["  "])
    with pytest.raises(errors.UsageError):
        build(icon_path=str(tmp_path / "missing.png"))
    with pytest.raises(errors.UsageError):
        build(entitlements_path=str(tmp_path / "missing.plist"))


def test_build_customization_treats_an_empty_entitlements_dict_as_noop(tmp_path):
    empty = tmp_path / "empty.plist"
    empty.write_bytes(plistlib.dumps({}))
    custom = customize.build_customization(
        name=None,
        remove_plugins=False,
        entitlements_path=str(empty),
        min_os=None,
        supported_devices=None,
        icon_path=None,
    )
    assert custom.extra_entitlements is None


# ------------------------------------------------------ icon replacement


def test_replace_app_icon_missing_source_is_a_usage_error(extracted):
    with pytest.raises(errors.UsageError):
        customize.replace_app_icon(
            extracted.main_bundle, extracted.main_bundle.root / "nope.png"
        )


def test_replace_app_icon_without_sips_is_a_transport_error(
    extracted, tmp_path, monkeypatch
):
    source = tmp_path / "icon.png"
    _write_png(source, 32)
    monkeypatch.setattr(customize, "_which_tool", lambda name: None)
    with pytest.raises(errors.TransportError):
        customize.replace_app_icon(extracted.main_bundle, source)


def test_replace_app_icon_without_references_fails_cleanly(extracted, tmp_path):
    """The fixture app has no CFBundleIcons/CFBundleIconFiles entries, so
    the flag must fail with a clear error, not corrupt the plist."""
    source = tmp_path / "icon.png"
    _write_png(source, 32)
    info_before = extracted.main_bundle.info_plist_path.read_bytes()
    with pytest.raises(errors.IPAError, match="icon"):
        customize.replace_app_icon(extracted.main_bundle, source)
    assert extracted.main_bundle.info_plist_path.read_bytes() == info_before


def test_replace_app_icon_rejects_unsafe_references(extracted, tmp_path):
    bundle = extracted.main_bundle
    values = _info(bundle)
    values["CFBundleIconFiles"] = ["../../etc/passwd"]
    bundle.info_plist_path.write_bytes(plistlib.dumps(values))
    source = tmp_path / "icon.png"
    _write_png(source, 32)
    with pytest.raises(errors.IPAError, match="unsafe"):
        customize.replace_app_icon(bundle, source)


@require_sips
def test_replace_app_icon_updates_all_scale_variants(extracted, tmp_path):
    bundle = extracted.main_bundle
    values = _info(bundle)
    values["CFBundleIcons"] = {
        "CFBundlePrimaryIcon": {"CFBundleIconFiles": ["AppIcon60x60"]}
    }
    # a legacy single-file reference whose size comes from the file
    values["CFBundleIconFile"] = "logo"
    bundle.info_plist_path.write_bytes(plistlib.dumps(values))
    _write_png(bundle.root / "AppIcon60x60.png", 16)
    _write_png(bundle.root / "AppIcon60x60@2x.png", 16)
    _write_png(bundle.root / "logo.png", 57)
    source = tmp_path / "icon.png"
    _write_png(source, 64, color=(0, 128, 255))
    replaced = customize.replace_app_icon(bundle, source)
    assert sorted(replaced) == [
        "AppIcon60x60.png",
        "AppIcon60x60@2x.png",
        "logo.png",
    ]
    # sizes come from the name (60, 60x2) or from the measured file (57)
    assert _pixel_width(bundle.root / "AppIcon60x60.png") == 60
    assert _pixel_width(bundle.root / "AppIcon60x60@2x.png") == 120
    assert _pixel_width(bundle.root / "logo.png") == 57
    # plist entries stay valid; nothing was renamed or corrupted
    values_after = _info(bundle)
    assert values_after["CFBundleIcons"]["CFBundlePrimaryIcon"] == {
        "CFBundleIconFiles": ["AppIcon60x60"]
    }
    assert values_after["CFBundleIconFile"] == "logo"
    assert values_after["CFBundleIdentifier"] == "com.example.fixture"


@require_sips
def test_replace_app_icon_creates_missing_size_named_files(extracted, tmp_path):
    bundle = extracted.main_bundle
    values = _info(bundle)
    # a size-named reference with no file gets created; a reference
    # without a size and without a file is skipped, best effort
    values["CFBundleIconFiles"] = ["AppIcon76x76", "mystery-ref"]
    bundle.info_plist_path.write_bytes(plistlib.dumps(values))
    source = tmp_path / "icon.png"
    _write_png(source, 64)
    replaced = customize.replace_app_icon(bundle, source)
    assert replaced == ["AppIcon76x76.png"]
    assert _pixel_width(bundle.root / "AppIcon76x76.png") == 76


@require_sips
def test_replace_app_icon_finds_icons_stored_in_subdirectories(extracted, tmp_path):
    bundle = extracted.main_bundle
    values = _info(bundle)
    values["CFBundleIconFiles"] = ["AppIcon60x60"]
    bundle.info_plist_path.write_bytes(plistlib.dumps(values))
    nested = bundle.root / "Assets"
    _write_png(nested / "AppIcon60x60.png", 60)
    source = tmp_path / "icon.png"
    _write_png(source, 64)
    replaced = customize.replace_app_icon(bundle, source)
    assert replaced == ["Assets/AppIcon60x60.png"]
    assert _pixel_width(nested / "AppIcon60x60.png") == 60


@require_sips
def test_replace_app_icon_rejects_an_unreadable_source(extracted, tmp_path):
    bundle = extracted.main_bundle
    values = _info(bundle)
    values["CFBundleIconFiles"] = ["AppIcon60x60"]
    bundle.info_plist_path.write_bytes(plistlib.dumps(values))
    _write_png(bundle.root / "AppIcon60x60.png", 60)
    source = tmp_path / "icon.png"
    source.write_bytes(b"definitely not an image")
    with pytest.raises(errors.IPAError, match="sips"):
        customize.replace_app_icon(bundle, source)
    # the untouched bundle icon is still the original one
    assert _pixel_width(bundle.root / "AppIcon60x60.png") == 60


@require_sips
def test_replace_app_icon_reports_a_pure_asset_catalog(extracted, tmp_path):
    bundle = extracted.main_bundle
    values = _info(bundle)
    values["CFBundleIcons"] = {"CFBundlePrimaryIcon": {"CFBundleIconName": "AppIcon"}}
    bundle.info_plist_path.write_bytes(plistlib.dumps(values))
    source = tmp_path / "icon.png"
    _write_png(source, 32)
    with pytest.raises(errors.IPAError, match="asset catalog"):
        customize.replace_app_icon(bundle, source)
