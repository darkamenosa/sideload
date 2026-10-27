"""Per account and per device cache of developer resources.

Caches what Apple reissues slowly and limits strictly: App IDs (10 at a
time on free accounts, expiring after 7 days), registered devices, and
provisioning profiles (7 day validity on free accounts). Everything is
plain JSON or raw profile bytes under the AppPaths layout; secrets such
as the signing private key and the session token are NOT cached here,
they live in the keychain (keychain.py).

Staleness policy (pinned here, implemented by GLUE agent):
    profiles     always revalidated against expiration_date and never
                 reused if expired; re-download is automatic
    app ids      re-listed (ios/listAppIds.action) on every sign run;
                 the on disk list is only a mirror for offline display
    devices      re-listed (ios/listDevices.action) on every install run
    install records  kept until the corresponding app is uninstalled

Ownership: shared infrastructure (GLUE agent). The SIGN agent reads and
writes through this interface; it must not touch files directly.
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime
from pathlib import Path

from sideload.config import (
    AppPaths,
    _safe_component,
    atomic_write_bytes,
    atomic_write_json,
    load_json,
    load_json_list,
)
from sideload.errors import ProfileError
from sideload.models import (
    AppIDRecord,
    DeviceRecord,
    InstallRecord,
    ProvisioningProfile,
    Team,
    TeamType,
)

# Keys used in the accounts/<dsid>/ JSON mirrors.
KEY_APP_IDS = "app_ids"
KEY_DEVICES = "devices"
KEY_TEAM = "team"

# Additional mirror bookkeeping keys (GLUE addition).
KEY_FIRST_SEEN = "first_seen"
KEY_SAVED_AT = "saved_at"


class ResourceCache:
    """JSON backed resource cache rooted at an AppPaths layout.

    Constructor (not pinned in the skeleton): pass the resolved
    AppPaths layout. All writes are atomic with 0600 permissions.
    """

    def __init__(self, paths: AppPaths) -> None:
        self.paths = paths

    # -------------------------------------------------------------- paths

    def _team_path(self, dsid: str) -> Path:
        return self.paths.account_dir(dsid) / "team.json"

    def _app_ids_path(self, dsid: str) -> Path:
        return self.paths.account_dir(dsid) / "appids.json"

    def _devices_path(self, dsid: str) -> Path:
        return self.paths.account_dir(dsid) / "devices.json"

    def _profiles_dir(self, dsid: str) -> Path:
        return self.paths.account_dir(dsid) / "profiles"

    # --------------------------------------------------------------- team

    def load_team(self, dsid: str) -> Team | None:
        """Return the cached team for this account, if any."""
        raw = load_json(self._team_path(dsid))
        if raw is None:
            return None
        return _team_from_dict(raw.get(KEY_TEAM))

    def save_team(self, dsid: str, team: object) -> None:
        """Persist the selected team for this account."""
        if isinstance(team, Team):
            payload: dict[str, object] = {KEY_TEAM: _team_to_dict(team)}
        elif isinstance(team, dict):
            payload = {KEY_TEAM: dict(team)}
        else:
            raise TypeError(f"cannot cache team of type {type(team).__name__}")
        atomic_write_json(self._team_path(dsid), payload)

    # ------------------------------------------------------------ App IDs

    def load_app_ids(self, dsid: str) -> list[AppIDRecord]:
        """Return the cached App ID list (may be empty or stale)."""
        raw = load_json(self._app_ids_path(dsid))
        if raw is None:
            return []
        items = raw.get(KEY_APP_IDS)
        if not isinstance(items, list):
            return []
        records = (_app_id_from_dict(item) for item in items if isinstance(item, dict))
        return [record for record in records if record is not None]

    def save_app_ids(self, dsid: str, app_ids: list[AppIDRecord]) -> None:
        """Mirror the freshly listed App IDs for this account."""
        path = self._app_ids_path(dsid)
        raw = load_json(path) or {}
        first_seen: dict[str, str] = {}
        existing = raw.get(KEY_FIRST_SEEN)
        if isinstance(existing, dict):
            first_seen = {str(key): str(value) for key, value in existing.items()}
        now = datetime.now(UTC).isoformat()
        for app_id in app_ids:
            first_seen.setdefault(app_id.identifier, now)
        payload: dict[str, object] = {
            KEY_APP_IDS: [_app_id_to_dict(app_id) for app_id in app_ids],
            KEY_FIRST_SEEN: first_seen,
            KEY_SAVED_AT: now,
        }
        atomic_write_json(path, payload)

    def app_id_first_seen(self, dsid: str) -> dict[str, datetime]:
        """When each cached App ID was first mirrored (for quota hints).

        Free App IDs expire 7 days after creation and Apple does not
        expose the creation date, so the first mirror time is the best
        available approximation.
        """
        raw = load_json(self._app_ids_path(dsid))
        existing = raw.get(KEY_FIRST_SEEN) if raw is not None else None
        result: dict[str, datetime] = {}
        if not isinstance(existing, dict):
            return result
        for identifier, value in existing.items():
            parsed = _parse_datetime(value)
            if parsed is not None:
                result[str(identifier)] = parsed
        return result

    def find_app_id(self, dsid: str, bundle_id: str) -> AppIDRecord | None:
        """Cached App ID whose identifier matches the resigned bundle id."""
        for app_id in self.load_app_ids(dsid):
            if app_id.bundle_identifier == bundle_id:
                return app_id
        return None

    # ------------------------------------------------------------ devices

    def load_devices(self, dsid: str) -> list[DeviceRecord]:
        """Return the cached team device registrations."""
        raw = load_json(self._devices_path(dsid))
        if raw is None:
            return []
        items = raw.get(KEY_DEVICES)
        if not isinstance(items, list):
            return []
        records = (_device_record_from_dict(item) for item in items if isinstance(item, dict))
        return [record for record in records if record is not None]

    def save_devices(self, dsid: str, devices: list[DeviceRecord]) -> None:
        """Mirror the freshly listed team devices."""
        payload: dict[str, object] = {
            KEY_DEVICES: [_device_record_to_dict(record) for record in devices],
            KEY_SAVED_AT: datetime.now(UTC).isoformat(),
        }
        atomic_write_json(self._devices_path(dsid), payload)

    # ----------------------------------------------------------- profiles

    def load_profile(self, dsid: str, profile_uuid: str) -> ProvisioningProfile | None:
        """Load a cached profile by UUID; returns None if absent.

        Expiry is not filtered here; callers (and
        find_profile_for_bundle) apply the staleness policy.
        """
        try:
            safe_uuid = _safe_component(profile_uuid, "profile UUID")
        except ValueError as exc:
            raise ProfileError(str(exc)) from exc
        summary_path = self._profiles_dir(dsid) / f"{safe_uuid}.json"
        return _read_profile(summary_path)

    def find_profile_for_bundle(self, dsid: str, bundle_id: str) -> ProvisioningProfile | None:
        """Newest cached profile whose application-identifier matches
        the given resigned bundle id, or None when nothing fresh exists.

        Free profiles expire 7 days after issuance; expired profiles are
        never returned here so the caller re-downloads automatically.
        """
        profiles_dir = self._profiles_dir(dsid)
        if not profiles_dir.is_dir():
            return None
        now = datetime.now(UTC)
        best: ProvisioningProfile | None = None
        for summary_path in sorted(profiles_dir.glob("*.json")):
            profile = _read_profile(summary_path)
            if profile is None:
                continue
            if not _profile_matches_bundle(profile, bundle_id):
                continue
            if _profile_expired(profile, now):
                continue
            if best is None or profile.expiration_date > best.expiration_date:
                best = profile
        return best

    def save_profile(self, dsid: str, profile: ProvisioningProfile) -> None:
        """Store the profile CMS bytes and a summary record."""
        if not profile.uuid:
            raise ProfileError("cannot cache a profile without a UUID")
        try:
            safe_uuid = _safe_component(profile.uuid, "profile UUID")
        except ValueError as exc:
            raise ProfileError(str(exc)) from exc
        profiles_dir = self._profiles_dir(dsid)
        profiles_dir.mkdir(parents=True, exist_ok=True)
        atomic_write_bytes(
            profiles_dir / f"{safe_uuid}.mobileprovision", profile.data
        )
        atomic_write_json(
            profiles_dir / f"{safe_uuid}.json", _profile_to_dict(profile)
        )

    # ----------------------------------------------------- install records

    def record_install(self, record: InstallRecord) -> None:
        """Remember how an app was signed for one device and account."""
        path = self.paths.install_records_path(record.udid)
        entries = [
            entry
            for entry in load_json_list(path)
            if isinstance(entry, dict)
        ]
        kept = [
            entry
            for entry in entries
            if not (
                str(entry.get("resigned_bundle_id", "")) == record.resigned_bundle_id
                and str(entry.get("dsid", "")) == record.dsid
            )
        ]
        kept.append(_install_record_to_dict(record))
        atomic_write_json(path, kept)

    def load_install_records(self, udid: str) -> list[InstallRecord]:
        """All install records for a device, newest first."""
        path = self.paths.install_records_path(udid)
        raw = load_json_list(path)
        records = (
            _install_record_from_dict(entry)
            for entry in raw
            if isinstance(entry, dict)
        )
        found = [record for record in records if record is not None]
        found.sort(key=lambda record: record.installed_at, reverse=True)
        return found

    def forget_install(self, udid: str, resigned_bundle_id: str) -> None:
        """Drop the install record after a successful uninstall."""
        path = self.paths.install_records_path(udid)
        entries = [
            entry
            for entry in load_json_list(path)
            if isinstance(entry, dict)
        ]
        kept = [
            entry
            for entry in entries
            if str(entry.get("resigned_bundle_id", "")) != resigned_bundle_id
        ]
        atomic_write_json(path, kept)


# ------------------------------------------------------------ serialization


def _normalize_dt(value: datetime) -> datetime:
    """Assume UTC for naive datetimes so comparisons never blow up."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


def _parse_datetime(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return _normalize_dt(datetime.fromisoformat(value))
    except ValueError:
        return None


def _team_to_dict(team: Team) -> dict[str, object]:
    return {
        "identifier": team.identifier,
        "name": team.name,
        "type": team.team_type.value,
    }


def _team_from_dict(raw: object) -> Team | None:
    if not isinstance(raw, dict):
        return None
    team_type_raw = raw.get("type")
    try:
        team_type = (
            TeamType(str(team_type_raw))
            if isinstance(team_type_raw, str)
            else TeamType.UNKNOWN
        )
    except ValueError:
        team_type = TeamType.UNKNOWN
    identifier = raw.get("identifier")
    name = raw.get("name")
    if not isinstance(identifier, str) or not isinstance(name, str):
        return None
    return Team(identifier=identifier, name=name, team_type=team_type)


def _app_id_to_dict(app_id: AppIDRecord) -> dict[str, object]:
    return {
        "identifier": app_id.identifier,
        "name": app_id.name,
        "bundle_identifier": app_id.bundle_identifier,
        "features": _jsonable(app_id.features),
    }


def _app_id_from_dict(raw: object) -> AppIDRecord | None:
    if not isinstance(raw, dict):
        return None
    identifier = raw.get("identifier")
    name = raw.get("name")
    bundle_identifier = raw.get("bundle_identifier")
    if not isinstance(identifier, str) or not isinstance(bundle_identifier, str):
        return None
    features = raw.get("features")
    return AppIDRecord(
        identifier=identifier,
        name=name if isinstance(name, str) else bundle_identifier,
        bundle_identifier=bundle_identifier,
        features=features if isinstance(features, dict) else {},
    )


def _device_record_to_dict(record: DeviceRecord) -> dict[str, object]:
    return {"name": record.name, "identifier": record.identifier}


def _device_record_from_dict(raw: object) -> DeviceRecord | None:
    if not isinstance(raw, dict):
        return None
    name = raw.get("name")
    identifier = raw.get("identifier")
    if not isinstance(identifier, str):
        return None
    return DeviceRecord(
        name=name if isinstance(name, str) else identifier,
        identifier=identifier,
    )


def _install_record_to_dict(record: InstallRecord) -> dict[str, object]:
    return {
        "original_bundle_id": record.original_bundle_id,
        "resigned_bundle_id": record.resigned_bundle_id,
        "app_id_identifier": record.app_id_identifier,
        "profile_uuid": record.profile_uuid,
        "dsid": record.dsid,
        "udid": record.udid,
        "installed_at": record.installed_at.isoformat(),
    }


def _required_str(raw: dict[str, object], key: str) -> str | None:
    value = raw.get(key)
    return value if isinstance(value, str) and value else None


def _install_record_from_dict(raw: object) -> InstallRecord | None:
    if not isinstance(raw, dict):
        return None
    original_bundle_id = _required_str(raw, "original_bundle_id")
    resigned_bundle_id = _required_str(raw, "resigned_bundle_id")
    app_id_identifier = _required_str(raw, "app_id_identifier")
    profile_uuid = _required_str(raw, "profile_uuid")
    dsid = _required_str(raw, "dsid")
    udid = _required_str(raw, "udid")
    if (
        original_bundle_id is None
        or resigned_bundle_id is None
        or app_id_identifier is None
        or profile_uuid is None
        or dsid is None
        or udid is None
    ):
        return None
    installed_at = _parse_datetime(raw.get("installed_at"))
    if installed_at is None:
        return None
    return InstallRecord(
        original_bundle_id=original_bundle_id,
        resigned_bundle_id=resigned_bundle_id,
        app_id_identifier=app_id_identifier,
        profile_uuid=profile_uuid,
        dsid=dsid,
        udid=udid,
        installed_at=installed_at,
    )


def _jsonable(value: object) -> object:
    """Convert plist values into JSON safe primitives."""
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _profile_to_dict(profile: ProvisioningProfile) -> dict[str, object]:
    return {
        "identifier": profile.identifier,
        "uuid": profile.uuid,
        "name": profile.name,
        "team_identifier": profile.team_identifier,
        "bundle_identifier": profile.bundle_identifier,
        "creation_date": profile.creation_date.isoformat(),
        "expiration_date": profile.expiration_date.isoformat(),
        "entitlements": _jsonable(profile.entitlements),
        "device_ids": list(profile.device_ids),
        "developer_certificates": [
            base64.b64encode(certificate).decode("ascii")
            for certificate in profile.developer_certificates
        ],
        "is_free": profile.is_free,
    }


def _profile_from_dict(raw: dict[str, object], data: bytes) -> ProvisioningProfile | None:
    creation = _parse_datetime(raw.get("creation_date"))
    expiration = _parse_datetime(raw.get("expiration_date"))
    if creation is None or expiration is None:
        return None
    device_ids = raw.get("device_ids")
    certificates = raw.get("developer_certificates")
    entitlements = raw.get("entitlements")
    bundle_identifier = raw.get("bundle_identifier")

    def as_str(key: str) -> str:
        value = raw.get(key)
        return value if isinstance(value, str) else ""

    return ProvisioningProfile(
        identifier=as_str("identifier"),
        uuid=as_str("uuid"),
        name=as_str("name"),
        team_identifier=as_str("team_identifier"),
        bundle_identifier=bundle_identifier if isinstance(bundle_identifier, str) else "",
        creation_date=creation,
        expiration_date=expiration,
        entitlements=entitlements if isinstance(entitlements, dict) else {},
        device_ids=tuple(str(item) for item in device_ids) if isinstance(device_ids, list) else (),
        developer_certificates=(
            tuple(base64.b64decode(str(item)) for item in certificates)
            if isinstance(certificates, list)
            else ()
        ),
        is_free=bool(raw.get("is_free", False)),
        data=data,
    )


def _read_profile(summary_path: Path) -> ProvisioningProfile | None:
    """Rebuild a profile from its summary JSON plus CMS bytes."""
    raw = load_json(summary_path)
    if raw is None:
        return None
    data_path = summary_path.with_suffix(".mobileprovision")
    if not data_path.is_file():
        return None
    try:
        data = data_path.read_bytes()
    except OSError:
        return None
    return _profile_from_dict(raw, data)


def _profile_matches_bundle(profile: ProvisioningProfile, bundle_id: str) -> bool:
    """True when the profile was issued for this resigned bundle id."""
    application_identifier = profile.entitlements.get("application-identifier")
    if (
        isinstance(application_identifier, str)
        and application_identifier == f"{profile.team_identifier}.{bundle_id}"
    ):
        return True
    return profile.bundle_identifier == bundle_id


def _profile_expired(profile: ProvisioningProfile, now: datetime) -> bool:
    """True when the profile expiration date has passed (7 day wall)."""
    return _normalize_dt(profile.expiration_date) <= _normalize_dt(now)
