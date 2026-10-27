"""Parsing and validation of .mobileprovision files.

A .mobileprovision is a CMS (PKCS#7) signed XML plist. Parsing options,
in order of preference:

    1. "security cms -D -i <profile>" (macOS system tool, always present)
    2. cryptography's pkcs7 loader as a fallback

The plist keys consumed are verified against AltSign
(AltSign/Model/Apple API/ALTProvisioningProfile.m):
    Name, UUID, TeamIdentifier[0], CreationDate, ExpirationDate,
    Entitlements, ProvisionedDevices, DeveloperCertificates (DER blobs),
    LocalProvision (true for free personal team profiles).

Ownership: SIGN agent.
"""

from __future__ import annotations

import plistlib
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from xml.parsers.expat import ExpatError

from sideload.errors import (
    BundleIDMismatchError,
    DeviceNotProvisionedError,
    ProfileError,
    ProfileExpiredError,
)
from sideload.models import ProvisioningProfile

_CMS_TIMEOUT = 30.0
_XML_PLIST_START = b"<?xml"
_XML_PLIST_END = b"</plist>"

# Keys the profile plist must carry to be usable at all. ProvisionedDevices
# and DeveloperCertificates may legitimately be absent (adhoc/universal
# profiles), so they default instead of failing the parse.
_REQUIRED_KEYS = (
    "Name",
    "UUID",
    "TeamIdentifier",
    "CreationDate",
    "ExpirationDate",
    "Entitlements",
)

_KEY_APPLICATION_IDENTIFIER = "application-identifier"


def _decode_cms(data: bytes) -> bytes:
    """Decode the CMS envelope with the macOS "security" tool."""
    with tempfile.NamedTemporaryFile(
        prefix="sideload-profile-", suffix=".mobileprovision", delete=False
    ) as handle:
        handle.write(data)
        temp_path = handle.name
    try:
        result = subprocess.run(
            ["security", "cms", "-D", "-i", temp_path],
            check=False,
            capture_output=True,
            timeout=_CMS_TIMEOUT,
        )
    except FileNotFoundError as exc:
        raise ProfileError(
            "the security tool was not found on this Mac", hint=(
                "install Xcode Command Line Tools: xcode-select --install"
            )
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise ProfileError("security cms timed out decoding the profile") from exc
    finally:
        Path(temp_path).unlink(missing_ok=True)
    if result.returncode != 0 or not result.stdout:
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise ProfileError(f"security cms could not decode the profile: {detail}")
    return result.stdout


def _decode_best_effort(data: bytes) -> bytes:
    """CMS decode via security, falling back to a raw embedded plist.

    Some toolchains emit .mobileprovision files that are bare XML
    plists without the CMS envelope; scanning for the plist body keeps
    sideload usable on those without adding a dependency.
    """
    try:
        return _decode_cms(data)
    except ProfileError:
        start = data.find(_XML_PLIST_START)
        if start < 0:
            raise
        end = data.find(_XML_PLIST_END, start)
        if end < 0:
            return data[start:]
        return data[start : end + len(_XML_PLIST_END)]


def parse_mobileprovision(data: bytes) -> ProvisioningProfile:
    """Decode CMS bytes into a ProvisioningProfile model.

    Raises ProfileError when the CMS envelope or the plist is invalid
    or when required keys are missing.

    The model identifier is the profile UUID here; when Apple hands the
    profile to developer.py it is replaced with the provisioningProfileId
    that ios/deleteProvisioningProfile.action needs.
    """
    plist_bytes = _decode_best_effort(data)
    try:
        parsed: object = plistlib.loads(plist_bytes)
    except (plistlib.InvalidFileException, ExpatError, ValueError) as exc:
        raise ProfileError(f"profile plist is unreadable: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ProfileError("profile plist root is not a dictionary")
    plist: dict[str, Any] = parsed
    missing = [key for key in _REQUIRED_KEYS if key not in plist]
    if missing:
        raise ProfileError(f"profile plist is missing keys: {', '.join(missing)}")

    name = _string_value(plist["Name"])
    uuid_value = _string_value(plist["UUID"])

    team_ids = plist["TeamIdentifier"]
    if not isinstance(team_ids, list) or not team_ids:
        raise ProfileError("profile TeamIdentifier is empty")
    team_identifier = _string_value(team_ids[0])

    creation_date = _date_value(plist["CreationDate"], "CreationDate")
    expiration_date = _date_value(plist["ExpirationDate"], "ExpirationDate")

    entitlements = plist["Entitlements"]
    if not isinstance(entitlements, dict):
        raise ProfileError("profile Entitlements is not a dictionary")

    application_identifier = _string_value(
        entitlements.get(_KEY_APPLICATION_IDENTIFIER)
    )
    if "." in application_identifier:
        bundle_identifier = application_identifier.split(".", 1)[1]
    else:
        bundle_identifier = ""

    devices_raw = plist.get("ProvisionedDevices")
    device_ids: tuple[str, ...] = ()
    if isinstance(devices_raw, list):
        device_ids = tuple(_string_value(item) for item in devices_raw)

    certificates_raw = plist.get("DeveloperCertificates")
    developer_certificates: tuple[bytes, ...] = ()
    if isinstance(certificates_raw, list):
        developer_certificates = tuple(
            bytes(item)
            for item in certificates_raw
            if isinstance(item, (bytes, bytearray))
        )

    return ProvisioningProfile(
        identifier=uuid_value,
        uuid=uuid_value,
        name=name,
        team_identifier=team_identifier,
        bundle_identifier=bundle_identifier,
        creation_date=creation_date,
        expiration_date=expiration_date,
        entitlements=dict(entitlements),
        device_ids=device_ids,
        developer_certificates=developer_certificates,
        is_free=bool(plist.get("LocalProvision", False)),
        data=data,
    )


def _string_value(value: object) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    return ""


def _date_value(value: object, label: str) -> datetime:
    if isinstance(value, datetime):
        return value
    raise ProfileError(f"profile {label} is not a date")


def profile_expiration(profile: ProvisioningProfile) -> datetime:
    """The profile expiration date (free profiles: 7 days from issuance)."""
    return profile.expiration_date


def assert_profile_usable(
    profile: ProvisioningProfile,
    udid: str,
    bundle_id: str,
    now: datetime | None = None,
) -> None:
    """Validate a profile for one install and raise on any problem.

    Checks, in order:
        1. expiration date is in the future (ProfileExpiredError)
        2. the device UDID is in ProvisionedDevices, hyphenless
           comparison included (DeviceNotProvisionedError)
        3. the profile application-identifier (TEAMID.bundle) matches
           the resigned bundle id (BundleIDMismatchError)
        4. the signing certificate DER appears in DeveloperCertificates
           (ProfileError listing what to regenerate)

    Note on check 4: this method has no certificate parameter in the
    frozen interface, so it asserts the profile carries at least one
    DeveloperCertificate; use certificate_matches_profile for the
    per-certificate comparison.
    """
    moment = now if now is not None else datetime.now(UTC)
    if _as_utc(profile.expiration_date) <= moment:
        raise ProfileExpiredError(
            f"provisioning profile {profile.uuid} expired at "
            f"{profile.expiration_date.isoformat()}",
            hint="sign again to download a fresh profile (free profiles "
            "expire 7 days after issuance)",
        )

    if udid not in profile.device_ids and not any(
        _normalize_udid(udid) == _normalize_udid(device)
        for device in profile.device_ids
    ):
        raise DeviceNotProvisionedError(
            f"device {udid} is not in profile {profile.uuid}",
            hint="register the device with the team and sign again "
            "(it is registered automatically during sideload install)",
        )

    application_identifier = profile.entitlements.get(_KEY_APPLICATION_IDENTIFIER)
    if not isinstance(application_identifier, str) or not application_identifier:
        raise ProfileError(
            f"profile {profile.uuid} has no application-identifier entitlement"
        )
    if "." in application_identifier:
        profile_bundle_id = application_identifier.split(".", 1)[1]
    else:
        profile_bundle_id = application_identifier
    if profile_bundle_id != bundle_id:
        raise BundleIDMismatchError(
            f"profile {profile.uuid} is for bundle id {profile_bundle_id!r} "
            f"but the app will be resigned as {bundle_id!r}",
            hint="the cached profile belongs to a different bundle id; "
            "sign again so a matching App ID and profile are created",
        )

    if not profile.developer_certificates:
        raise ProfileError(
            f"profile {profile.uuid} contains no DeveloperCertificates; "
            "regenerate the signing certificate and re-download the profile"
        )


def certificate_matches_profile(
    certificate_der: bytes,
    profile: ProvisioningProfile,
) -> bool:
    """True when the certificate is one of the profile's
    DeveloperCertificates entries.
    """
    return certificate_der in profile.developer_certificates


def _normalize_udid(udid: str) -> str:
    return udid.replace("-", "").lower()


def _as_utc(moment: datetime) -> datetime:
    if moment.tzinfo is None:
        return moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC)
