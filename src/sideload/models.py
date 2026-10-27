"""Data models shared across module boundaries.

Field names mirror the Apple API responses as parsed by AltSign
(AltSign/Model/Apple API/*.m) so the auth and sign agents can map
responses without consulting each other. All classes are plain
dataclasses with no behavior; serialization helpers live in the
modules that own the storage (keychain.py, cache.py).

Ownership: shared (GLUE agent). Agents must not add behavior here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum


class TeamType(Enum):
    """Team type as reported by listTeams.action.

    AltSign maps the raw strings: "Company/Organization", "Individual"
    (free when the single membership name contains "free"), otherwise
    unknown.
    """

    FREE = "free"
    INDIVIDUAL = "individual"
    ORGANIZATION = "organization"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class AnisetteData:
    """One anisette header set, valid for a single Apple API request.

    Header mapping (verified in AltServer/AnisetteDataManager.swift and
    SideStore omnisette/src/aos_kit.rs):
        machine_id        X-Apple-I-MD-M
        one_time_password X-Apple-I-MD
        local_user_id     X-Apple-I-MD-LU
        routing_info      X-Apple-I-MD-RINFO (production value 84215040)
        device_unique_id  X-Mme-Device-Id
        device_serial     X-Apple-I-SRL-NO
        device_description X-MMe-Client-Info
    """

    machine_id: str
    one_time_password: str
    local_user_id: str
    routing_info: int
    device_unique_id: str
    device_serial: str
    device_description: str
    locale: str
    timezone: str
    client_time: str


@dataclass(frozen=True)
class Account:
    """The Apple developer view of the logged in user.

    Source: viewDeveloper.action response key "developer".
    """

    first_name: str
    last_name: str
    email: str
    dsid: str


@dataclass(frozen=True)
class AppleSession:
    """A Grand Slam session for the com.apple.gs.xcode.auth service.

    dsid is the "adsid" from the decrypted GSA login response; gs_token
    is the app token for com.apple.gs.xcode.auth sent as X-Apple-GS-Token
    on developerservices2 requests; token_expiry is the "expiry" value
    from the decrypted apptoken plist (epoch milliseconds).
    """

    dsid: str
    gs_token: str
    token_expiry: datetime
    account: Account


@dataclass(frozen=True)
class Team:
    """One team from listTeams.action.

    identifier is the raw "teamId", name the "name" key.
    """

    identifier: str
    name: str
    team_type: TeamType

    @property
    def is_free(self) -> bool:
        return self.team_type is TeamType.FREE


@dataclass(frozen=True)
class DeviceRecord:
    """A device registered with the team on Apple's side.

    Source keys: "name" and "deviceNumber" (ios/listDevices.action and
    ios/addDevice.action). identifier is the device UDID exactly as
    lockdownd reports it, for example 00008101-000000000000000E.
    """

    name: str
    identifier: str


@dataclass(frozen=True)
class DeveloperCertificate:
    """An IOS_DEVELOPMENT signing certificate issued to the team.

    certificate_pem is the PEM body Apple returns (certContent or
    base64 certificateContent). The matching private key never leaves
    the Mac: it is generated locally, used for the CSR, and stored in
    the sideload keychain (see keychain.py).
    """

    identifier: str
    machine_name: str
    machine_id: str
    certificate_pem: bytes
    expires_at: datetime | None = None


@dataclass(frozen=True)
class AppIDRecord:
    """One App ID registered with the team.

    Source keys: "appIdId" (identifier), "name", "identifier"
    (bundle_identifier) from ios/listAppIds.action and ios/addAppId.action.
    """

    identifier: str
    name: str
    bundle_identifier: str
    features: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class ProvisioningProfile:
    """A parsed .mobileprovision (CMS signed plist).

    Parsed keys, verified in AltSign ALTProvisioningProfile.m: Name,
    UUID, TeamIdentifier[0], CreationDate, ExpirationDate, Entitlements,
    ProvisionedDevices, DeveloperCertificates (DER blobs), and the free
    flag LocalProvision. data keeps the original CMS bytes for
    embedding as embedded.mobileprovision.
    """

    identifier: str
    uuid: str
    name: str
    team_identifier: str
    bundle_identifier: str
    creation_date: datetime
    expiration_date: datetime
    entitlements: dict[str, object]
    device_ids: tuple[str, ...]
    developer_certificates: tuple[bytes, ...]
    is_free: bool
    data: bytes

    def expires_within(self, seconds: float) -> bool:
        """True when the profile expires sooner than the given horizon."""
        now = datetime.now(self.expiration_date.tzinfo or UTC)
        return self.expiration_date <= now + timedelta(seconds=seconds)


@dataclass(frozen=True)
class IOSDevice:
    """A device visible over usbmux on this Mac."""

    udid: str
    name: str | None = None
    product_type: str | None = None
    product_version: str | None = None
    connection_type: str = "usb"
    paired: bool | None = None
    developer_mode_enabled: bool | None = None


@dataclass(frozen=True)
class InstalledApp:
    """One app listed by the device installation proxy."""

    bundle_identifier: str
    name: str | None = None
    version: str | None = None
    bundle_path: str | None = None


@dataclass(frozen=True)
class SigningIdentity:
    """The identity the signer uses for codesign or ldid.

    Exactly one mode is populated: keychain_identity is a keychain
    identity name usable with "codesign -s"; certificate_pem plus
    private_key_pem drive the ldid fallback directly.
    """

    team_identifier: str
    keychain_identity: str | None = None
    certificate_pem: bytes | None = None
    private_key_pem: bytes | None = None


@dataclass(frozen=True)
class InstallRecord:
    """Cache entry remembering how one IPA was signed and installed.

    Lets later installs reuse the same resigned bundle id, App ID, and
    profile for the same original bundle id, device, and account.

    ipa_path is the absolute path of the source IPA recorded at install
    time, so "sideload refresh" can re-sign the app before the 7 day
    free profile expires. It is optional because records written before
    the field existed load with None and refresh skips them.
    """

    original_bundle_id: str
    resigned_bundle_id: str
    app_id_identifier: str
    profile_uuid: str
    dsid: str
    udid: str
    installed_at: datetime
    ipa_path: str | None = None


@dataclass(frozen=True)
class SignResult:
    """Everything the sign pipeline produced for one input IPA."""

    output_ipa: str
    original_bundle_id: str
    resigned_bundle_id: str
    team: Team
    profile: ProvisioningProfile
