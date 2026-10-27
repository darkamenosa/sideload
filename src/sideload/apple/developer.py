"""Apple developer services client (developerservices2.apple.com).

Verified against AltSign (AltSign/Apple API/ALTAppleAPI.m). Request
contract for all plist actions:

    POST https://developerservices2.apple.com/services/QH65B2/<action>?clientId=XABBG36SBA
    Headers:
        Content-Type: text/x-xml-plist     User-Agent: Xcode
        Accept: text/x-xml-plist           Accept-Language: en-us
        X-Apple-App-Info: com.apple.gs.xcode.auth
        X-Xcode-Version: 11.2 (11B41)
        X-Apple-I-Identity-Id: <dsid>
        X-Apple-GS-Token: <gs token>
        X-Apple-I-MD-M / X-Apple-I-MD / X-Apple-I-MD-LU /
        X-Apple-I-MD-RINFO / X-Mme-Device-Id / X-MMe-Client-Info /
        X-Apple-I-Client-Time / X-Apple-Locale / X-Apple-I-TimeZone
        (anisette values)
    Body (XML plist): {"clientId": "XABBG36SBA",
        "protocolVersion": "QH65B2", "requestId": <UPPERCASE UUID>,
        "teamId": <team id, when action is team scoped>, <action params>}

Responses are XML plists; resultCode 0 means success, anything else is
an error with a userString. Known resultCodes mapped in errors.py:
    35    invalid input or device already registered
    3250  invalid certificate request
    7252  certificate does not exist
    8101  profile does not exist
    8201  App ID does not exist
    9100  App ID does not exist
    9120  App ID weekly creation limit reached (free accounts)
    9401  bundle identifier unavailable
    9412  invalid bundle identifier

A second, JSON:API style endpoint set lives at
https://developerservices2.apple.com/services/v1/ (AltSign
sendServicesRequest): POST with JSON body
{"urlEncodedQueryParams": "teamId=...&filter[certificateType]=..."},
Content-Type application/vnd.api+json, X-HTTP-Method-Override to tunnel
GET/DELETE, used only for listing and revoking certificates.

Action table (all POST, all relative to the QH65B2 base):
    listTeams.action                     -> {"teams": [{name, teamId,
                                            type, memberships:[...]}]}
    viewDeveloper.action                 -> {"developer": {...}}
    ios/listDevices.action               -> {"devices": [{name, deviceNumber}]}
    ios/addDevice.action                 body {deviceNumber, name}
                                        -> {"device": {name, deviceNumber}}
    ios/submitDevelopmentCSR.action      body {csrContent (PEM string),
                                            machineId (UUID), machineName}
                                        -> {"certRequest": {"id",
                                            "attributes": {certContent|
                                            certificateContent, machineName,
                                            machineId}}}
    ios/listAppIds.action                -> {"appIds": [{appIdId, name,
                                            identifier}]}
    ios/addAppId.action                  body {identifier, name (alnum)}
                                        -> {"appId": {...}}
    ios/updateAppId.action               body {appIdId, feature flags}
    ios/deleteAppId.action               body {appIdId}
    ios/downloadTeamProvisioningProfile.action
                                          body {appIdId}
                                        -> {"provisioningProfile":
                                            {"provisioningProfileId",
                                             "encodedProfile": <CMS bytes>}}
    ios/deleteProvisioningProfile.action  body {provisioningProfileId, teamId}

Ownership: SIGN agent. Depends only on AppleSession (produced by AUTH)
and AnisetteProvider; no other cross module dependencies.
"""

from __future__ import annotations

import base64
import binascii
import dataclasses
import json
import plistlib
import re
import uuid
from datetime import datetime
from typing import Any
from urllib.parse import quote

import requests

from sideload.apple.anisette import AnisetteProvider
from sideload.errors import (
    AppIDQuotaExceededError,
    BundleIdentifierUnavailableError,
    DeveloperAPIError,
    DeviceAlreadyRegisteredError,
    InvalidCertificateRequestError,
    SessionExpiredError,
)
from sideload.models import (
    Account,
    AppIDRecord,
    AppleSession,
    DeveloperCertificate,
    DeviceRecord,
    ProvisioningProfile,
    Team,
    TeamType,
)

DEVELOPER_BASE_URL = "https://developerservices2.apple.com/services/QH65B2/"
SERVICES_V1_BASE_URL = "https://developerservices2.apple.com/services/v1/"
CLIENT_ID = "XABBG36SBA"
PROTOCOL_VERSION = "QH65B2"
CERTIFICATE_TYPE = "IOS_DEVELOPMENT"

_REQUEST_TIMEOUT = 60.0

_HINT_APP_ID_QUOTA = (
    "Free Apple accounts can register 10 App IDs at a time and each expires "
    "after 7 days. Remove App IDs you no longer sideload or wait for the "
    "oldest to expire, then run the command again."
)
_HINT_BUNDLE_ID = (
    "The resigned bundle identifier must be unique across all teams. If it "
    "belongs to another team, sign again with a different --bundle-id."
)
_HINT_CSR = (
    "Apple rejected the certificate request. Remove the stored signing "
    "identity and retry so sideload generates a fresh key and CSR."
)
_HINT_PROFILE = (
    "The provisioning profile is no longer valid on Apple's side. Sign again "
    "to download a fresh profile."
)

# Result codes with dedicated exception classes in errors.py.
_CODE_APP_ID_QUOTA = 9120
_CODE_BUNDLE_ID_TAKEN = 9401
_CODE_BUNDLE_ID_INVALID = 9412
_CODE_CSR_REJECTED = 3250
_CODE_ALREADY_EXISTS = 35

# Keys tried when extracting the certificate body from an Apple response.
_CERT_CONTENT_KEYS = ("certContent", "certificateContent", "content")


def _as_str(value: object, default: str = "") -> str:
    """Best effort stringification of a plist/JSON scalar."""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    return default


def _as_dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def _sanitize_app_id_name(value: str) -> str:
    """Alphanumeric only, as AltSign does before ios/addAppId."""
    return re.sub(r"[^A-Za-z0-9]", "", value)


def _parse_expiry(value: object) -> datetime | None:
    """Parse an expiry scalar from Apple responses; None when unreadable."""
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            return datetime.fromisoformat(text)
        except ValueError:
            return None
    return None


def _decode_base64(data: bytes) -> bytes | None:
    try:
        return base64.b64decode(data, validate=False)
    except (binascii.Error, ValueError):
        return None


def _certificate_to_pem(content: object) -> bytes:
    """Normalize a certificate payload (PEM text, base64 DER, or raw DER)."""
    if isinstance(content, bytes):
        raw = content
    elif isinstance(content, str):
        raw = content.encode("utf-8")
    else:
        raise DeveloperAPIError("certificate payload has an unsupported type")
    if raw.lstrip().startswith(b"-----BEGIN CERTIFICATE-----"):
        return raw
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding

    for candidate in (_decode_base64(raw), raw):
        if candidate is None:
            continue
        try:
            certificate = x509.load_der_x509_certificate(candidate)
        except ValueError:
            continue
        return certificate.public_bytes(Encoding.PEM)
    raise DeveloperAPIError("certificate payload is neither PEM nor DER")


class DeveloperServiceClient:
    """Typed client over the QH65B2 plist action API."""

    def __init__(self, session: AppleSession, anisette: AnisetteProvider) -> None:
        """Store session credentials and prepare the HTTP client."""
        self._session = session
        self._anisette = anisette

    # ------------------------------------------------------------ account

    def fetch_developer(self) -> Account:
        """viewDeveloper.action; the logged in developer account."""
        response = self._send_action("viewDeveloper.action", {})
        developer = _as_dict(response.get("developer"))
        if not developer:
            raise DeveloperAPIError(
                "viewDeveloper.action returned no developer payload"
            )
        return Account(
            first_name=_as_str(developer.get("firstName")),
            last_name=_as_str(developer.get("lastName")),
            email=_as_str(developer.get("email")),
            dsid=_as_str(developer.get("dsid"), self._session.dsid),
        )

    def fetch_teams(self) -> list[Team]:
        """listTeams.action; all teams for the account.

        Raises AuthError via DeveloperAPIError if none are returned.
        A team with type "Individual" whose single membership name
        contains "free" is a free personal team (ALTTeam.m).
        """
        response = self._send_action("listTeams.action", {})
        teams: list[Team] = []
        for item in _as_list(response.get("teams")):
            team = self._team_from_response(_as_dict(item))
            if team is not None:
                teams.append(team)
        if not teams:
            raise DeveloperAPIError(
                "listTeams.action returned no teams for this account",
                hint="run: sideload auth login to refresh the session",
            )
        return teams

    def _team_from_response(self, item: dict[str, Any]) -> Team | None:
        team_id = _as_str(item.get("teamId"))
        if not team_id:
            return None
        membership_names: list[str] = []
        for membership in _as_list(item.get("memberships")):
            member = _as_dict(membership)
            for key in ("name", "membershipName", "description"):
                value = _as_str(member.get(key))
                if value:
                    membership_names.append(value)
        raw_type = _as_str(item.get("type")).lower()
        team_type = TeamType.UNKNOWN
        if "company" in raw_type or "organization" in raw_type:
            team_type = TeamType.ORGANIZATION
        elif "individual" in raw_type:
            team_type = TeamType.INDIVIDUAL
            if any("free" in name.lower() for name in membership_names):
                team_type = TeamType.FREE
        return Team(
            identifier=team_id,
            name=_as_str(item.get("name")),
            team_type=team_type,
        )

    # ------------------------------------------------------------ devices

    def fetch_devices(self, team: Team) -> list[DeviceRecord]:
        """ios/listDevices.action; devices registered with the team."""
        response = self._send_action("ios/listDevices.action", {}, team)
        records: list[DeviceRecord] = []
        for item in _as_list(response.get("devices")):
            device = _as_dict(item)
            records.append(
                DeviceRecord(
                    name=_as_str(device.get("name")),
                    identifier=_as_str(device.get("deviceNumber")),
                )
            )
        return records

    def register_device(self, name: str, udid: str, team: Team) -> DeviceRecord:
        """ios/addDevice.action; register this iPhone with the team.

        The udid is passed exactly as lockdownd reports it. Raises
        DeviceAlreadyRegisteredError when Apple reports code 35 with
        "already exists" in userString; callers treat that as success.
        """
        response = self._send_action(
            "ios/addDevice.action",
            {"deviceNumber": udid, "name": name},
            team,
        )
        device = _as_dict(response.get("device"))
        return DeviceRecord(
            name=_as_str(device.get("name"), name),
            identifier=_as_str(device.get("deviceNumber"), udid),
        )

    # ------------------------------------------------------- certificates

    def list_certificates(self, team: Team) -> list[DeveloperCertificate]:
        """List IOS_DEVELOPMENT certificates via the services/v1 JSON API
        (filter[certificateType]=IOS_DEVELOPMENT).
        """
        query = f"teamId={team.identifier}&filter[certificateType]={CERTIFICATE_TYPE}"
        payload = self._send_services("certificates", "GET", query)
        certificates: list[DeveloperCertificate] = []
        for item in _as_list(_as_dict(payload).get("data")):
            record = _as_dict(item)
            if record:
                certificates.append(self._developer_certificate(record))
        return certificates

    def create_development_certificate(
        self,
        csr_pem: str,
        machine_name: str,
        team: Team,
        machine_id: str | None = None,
    ) -> DeveloperCertificate:
        """ios/submitDevelopmentCSR.action with a locally generated CSR.

        machine_id is a random UUID persisted per machine by the caller.
        Raises InvalidCertificateRequestError for resultCode 3250.

        machine_id is the caller's persisted per-machine UUID; a random
        one is generated only when the caller has none, so Apple's
        records keep identifying the same Mac across certificates.
        """
        if not machine_id:
            machine_id = str(uuid.uuid4()).upper()
        response = self._send_action(
            "ios/submitDevelopmentCSR.action",
            {
                "csrContent": csr_pem,
                "machineId": machine_id,
                "machineName": machine_name,
            },
            team,
        )
        cert_request = _as_dict(response.get("certRequest"))
        if not cert_request:
            raise DeveloperAPIError(
                "ios/submitDevelopmentCSR.action returned no certRequest payload"
            )
        return self._developer_certificate(cert_request)

    def _developer_certificate(self, payload: dict[str, Any]) -> DeveloperCertificate:
        attributes = _as_dict(payload.get("attributes"))
        content: object = None
        for key in _CERT_CONTENT_KEYS:
            if key in attributes:
                content = attributes[key]
                break
            if key in payload:
                content = payload[key]
                break
        if content is None:
            raise DeveloperAPIError(
                "certificate response is missing certContent/certificateContent"
            )
        expires_at = _parse_expiry(
            attributes.get("expirationDate", attributes.get("expiresAt"))
        )
        machine_name = _as_str(
            attributes.get("machineName", attributes.get("name"))
        )
        return DeveloperCertificate(
            identifier=_as_str(payload.get("id")),
            machine_name=machine_name,
            machine_id=_as_str(attributes.get("machineId")),
            certificate_pem=_certificate_to_pem(content),
            expires_at=expires_at,
        )

    def revoke_certificate(
        self, certificate: DeveloperCertificate, team: Team
    ) -> None:
        """DELETE services/v1/certificates/<id> via method override.

        Free teams should keep few certificates; AltStore revokes the
        previous machine certificate before requesting a new one.
        """
        self._send_services(
            f"certificates/{quote(certificate.identifier, safe='')}",
            "DELETE",
            f"teamId={team.identifier}",
        )

    # ------------------------------------------------------------ App IDs

    def fetch_app_ids(self, team: Team) -> list[AppIDRecord]:
        """ios/listAppIds.action; every App ID registered to the team."""
        response = self._send_action("ios/listAppIds.action", {}, team)
        records: list[AppIDRecord] = []
        for item in _as_list(response.get("appIds")):
            app_id = _as_dict(item)
            if app_id:
                records.append(self._app_id_from_response(app_id))
        return records

    def _app_id_from_response(self, item: dict[str, Any]) -> AppIDRecord:
        features = item.get("features")
        return AppIDRecord(
            identifier=_as_str(item.get("appIdId")),
            name=_as_str(item.get("name")),
            bundle_identifier=_as_str(item.get("identifier")),
            features=features if isinstance(features, dict) else {},
        )

    def add_app_id(self, name: str, bundle_identifier: str, team: Team) -> AppIDRecord:
        """ios/addAppId.action; register one explicit App ID.

        The name is sanitized to alphanumeric characters (AltSign
        strips everything else). Raises AppIDQuotaExceededError for
        resultCode 9120 and BundleIdentifierUnavailableError for
        9401/9412.
        """
        clean_name = (
            _sanitize_app_id_name(name) or _sanitize_app_id_name(bundle_identifier)
        )
        response = self._send_action(
            "ios/addAppId.action",
            {"identifier": bundle_identifier, "name": clean_name},
            team,
        )
        app_id = _as_dict(response.get("appId"))
        if not app_id:
            raise DeveloperAPIError("ios/addAppId.action returned no appId payload")
        return self._app_id_from_response(app_id)

    def update_app_id(self, app_id: AppIDRecord, team: Team) -> AppIDRecord:
        """ios/updateAppId.action; push changed feature flags."""
        enabled_features = [key for key, value in app_id.features.items() if value]
        response = self._send_action(
            "ios/updateAppId.action",
            {
                "appIdId": app_id.identifier,
                "identifier": app_id.bundle_identifier,
                "name": _sanitize_app_id_name(app_id.name)
                or _sanitize_app_id_name(app_id.bundle_identifier),
                "features": enabled_features,
            },
            team,
        )
        updated = _as_dict(response.get("appId"))
        if not updated:
            raise DeveloperAPIError("ios/updateAppId.action returned no appId payload")
        return self._app_id_from_response(updated)

    def delete_app_id(self, app_id: AppIDRecord, team: Team) -> None:
        """ios/deleteAppId.action; free the weekly App ID quota."""
        self._send_action(
            "ios/deleteAppId.action", {"appIdId": app_id.identifier}, team
        )

    # ------------------------------------------------------------ profiles

    def fetch_provisioning_profile(
        self, app_id: AppIDRecord, team: Team
    ) -> ProvisioningProfile:
        """ios/downloadTeamProvisioningProfile.action for this App ID.

        Returns the CMS profile bytes parsed into ProvisioningProfile;
        free profiles are marked by the LocalProvision key. The profile
        embeds the team, the granted entitlements, and the registered
        device UDIDs; callers must verify expiry and device membership.

        The returned profile's identifier is the Apple
        provisioningProfileId (so delete_provisioning_profile works);
        profiles parsed straight from files keep the plist UUID there.
        """
        response = self._send_action(
            "ios/downloadTeamProvisioningProfile.action",
            {"appIdId": app_id.identifier},
            team,
        )
        profile_dict = _as_dict(response.get("provisioningProfile"))
        encoded = profile_dict.get("encodedProfile")
        if not isinstance(encoded, (bytes, bytearray)):
            raise DeveloperAPIError(
                "ios/downloadTeamProvisioningProfile.action "
                "returned no encodedProfile data"
            )
        # Imported lazily: developer.py must not depend on the signing
        # package at import time (see the module docstring contract).
        from sideload.signing.profile import parse_mobileprovision

        parsed = parse_mobileprovision(bytes(encoded))
        profile_id = _as_str(profile_dict.get("provisioningProfileId"))
        if profile_id and parsed.identifier != profile_id:
            parsed = dataclasses.replace(parsed, identifier=profile_id)
        return parsed

    def delete_provisioning_profile(
        self, profile: ProvisioningProfile, team: Team
    ) -> None:
        """ios/deleteProvisioningProfile.action; drop an unusable profile."""
        self._send_action(
            "ios/deleteProvisioningProfile.action",
            {"provisioningProfileId": profile.identifier},
            team,
        )

    # ------------------------------------------------------------- plumbing

    def _anisette_headers(self) -> dict[str, str]:
        """Fresh anisette headers; the OTP is single use per request."""
        anisette = self._anisette.get_anisette()
        return {
            "X-Apple-I-MD": anisette.one_time_password,
            "X-Apple-I-MD-M": anisette.machine_id,
            "X-Apple-I-MD-LU": anisette.local_user_id,
            "X-Apple-I-MD-RINFO": str(anisette.routing_info),
            "X-Mme-Device-Id": anisette.device_unique_id,
            "X-MMe-Client-Info": anisette.device_description,
            "X-Apple-I-Client-Time": anisette.client_time,
            "X-Apple-Locale": anisette.locale,
            "X-Apple-I-TimeZone": anisette.timezone,
            "X-Apple-I-SRL-NO": anisette.device_serial,
        }

    def _common_headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "text/x-xml-plist",
            "Accept": "text/x-xml-plist",
            "Accept-Language": "en-us",
            "User-Agent": "Xcode",
            "X-Apple-App-Info": "com.apple.gs.xcode.auth",
            "X-Xcode-Version": "11.2 (11B41)",
            "X-Apple-I-Identity-Id": self._session.dsid,
            "X-Apple-GS-Token": self._session.gs_token,
        }
        headers.update(self._anisette_headers())
        return headers

    def _send_action(
        self,
        action: str,
        parameters: dict[str, object],
        team: Team | None = None,
    ) -> dict[str, Any]:
        """POST one plist action and return the parsed response dict.

        Raises DeveloperAPIError (or a subclass for known resultCodes)
        when resultCode is non-zero. Must refresh anisette headers per
        request because the OTP is one time.
        """
        body: dict[str, object] = {
            "clientId": CLIENT_ID,
            "protocolVersion": PROTOCOL_VERSION,
            "requestId": str(uuid.uuid4()).upper(),
        }
        if team is not None:
            body["teamId"] = team.identifier
        body.update(parameters)
        url = f"{DEVELOPER_BASE_URL}{action}?clientId={CLIENT_ID}"
        try:
            response = requests.post(
                url,
                headers=self._common_headers(),
                data=plistlib.dumps(body, fmt=plistlib.FMT_XML),
                timeout=_REQUEST_TIMEOUT,
                allow_redirects=False,
            )
        except requests.RequestException as exc:
            raise DeveloperAPIError(f"{action} request failed: {exc}") from exc
        if response.status_code in (401, 403):
            raise SessionExpiredError(
                "Apple rejected the stored session; it has expired or been revoked.",
                hint="run: sideload auth login",
            )
        if response.status_code != 200:
            raise DeveloperAPIError(
                f"{action} returned HTTP {response.status_code}",
                user_string=response.text[:200],
            )
        try:
            parsed: object = plistlib.loads(response.content)
        except (plistlib.InvalidFileException, ValueError) as exc:
            raise DeveloperAPIError(
                f"{action} returned a response that is not an XML plist: {exc}"
            ) from exc
        if not isinstance(parsed, dict):
            raise DeveloperAPIError(f"{action} returned an unexpected plist root")
        if "resultCode" not in parsed:
            raise DeveloperAPIError(
                f"{action} response is missing resultCode",
                user_string=str(parsed)[:200],
            )
        result_code = parsed["resultCode"]
        if isinstance(result_code, bool) or not isinstance(result_code, int):
            raise DeveloperAPIError(
                f"{action} returned a non numeric resultCode: {result_code!r}"
            )
        if result_code != 0:
            if result_code == 1100:
                raise SessionExpiredError(
                    "Apple rejected the stored session; it has expired or been revoked.",
                    hint="run: sideload auth login",
                )
            user_string = _as_str(parsed.get("userString"))
            raise self._error_for(action, result_code, user_string)
        return parsed

    def _send_services(self, path: str, method: str, query: str) -> object:
        """One services/v1 JSON:API call tunneled through POST."""
        headers = self._common_headers()
        headers["Content-Type"] = "application/vnd.api+json"
        headers["Accept"] = "application/vnd.api+json"
        headers["X-HTTP-Method-Override"] = method
        url = f"{SERVICES_V1_BASE_URL}{path}"
        body = json.dumps({"urlEncodedQueryParams": query}).encode("utf-8")
        try:
            response = requests.post(
                url,
                headers=headers,
                data=body,
                timeout=_REQUEST_TIMEOUT,
                allow_redirects=False,
            )
        except requests.RequestException as exc:
            raise DeveloperAPIError(
                f"services/v1 {path} request failed: {exc}"
            ) from exc
        if response.status_code in (401, 403):
            raise SessionExpiredError(
                "Apple rejected the stored session; it has expired or been revoked.",
                hint="run: sideload auth login",
            )
        if response.status_code not in (200, 201, 204):
            raise DeveloperAPIError(
                f"services/v1 {path} returned HTTP {response.status_code}",
                user_string=response.text[:200],
            )
        if not response.content:
            return None
        try:
            return response.json()
        except ValueError as exc:
            raise DeveloperAPIError(
                f"services/v1 {path} returned invalid JSON: {exc}"
            ) from exc

    def _error_for(
        self, action: str, result_code: int, user_string: str
    ) -> DeveloperAPIError:
        """Map a non-zero resultCode onto the errors.py taxonomy."""
        label = user_string or f"resultCode {result_code}"
        message = f"{action} failed: {label}"
        if result_code == _CODE_APP_ID_QUOTA:
            return AppIDQuotaExceededError(
                message,
                result_code=result_code,
                user_string=user_string,
                hint=_HINT_APP_ID_QUOTA,
            )
        if result_code in (_CODE_BUNDLE_ID_TAKEN, _CODE_BUNDLE_ID_INVALID):
            return BundleIdentifierUnavailableError(
                message,
                result_code=result_code,
                user_string=user_string,
                hint=_HINT_BUNDLE_ID,
            )
        if result_code == _CODE_CSR_REJECTED:
            return InvalidCertificateRequestError(
                message,
                result_code=result_code,
                user_string=user_string,
                hint=_HINT_CSR,
            )
        lowered = user_string.lower()
        if result_code == _CODE_ALREADY_EXISTS and (
            "already exists" in lowered
            or "already registered" in lowered
            or action.endswith("addDevice.action")
        ):
            return DeviceAlreadyRegisteredError(
                message,
                result_code=result_code,
                user_string=user_string,
            )
        hint = None
        if action.startswith("ios/") and result_code in (8101, 8201, 9100):
            hint = _HINT_PROFILE
        return DeveloperAPIError(
            message,
            result_code=result_code,
            user_string=user_string,
            hint=hint,
        )
