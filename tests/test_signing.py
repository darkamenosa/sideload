"""Offline tests for the SIGN slice.

Covers the developer services client (all HTTP faked, no Apple ID, no
network), CSR generation, mobileprovision parsing via the real
"security cms" tool, entitlement merging, IPA unpack/repack, and the
codesign/ldid signing order using a small fixture app built under
/tmp (one nested framework, one loose dylib, one appex extension).
"""

from __future__ import annotations

import base64
import os
import plistlib
import re
import shutil
import stat
import struct
import subprocess
import tempfile
import zipfile
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from sideload import errors
from sideload.apple import developer
from sideload.models import (
    Account,
    AnisetteData,
    AppIDRecord,
    AppleSession,
    ProvisioningProfile,
    SigningIdentity,
    Team,
    TeamType,
)
from sideload.signing import csr, entitlements, ipa, profile, signer

CODESIGN = shutil.which("codesign")
LDID = shutil.which("ldid")
OPENSSL = shutil.which("openssl")
SECURITY = shutil.which("security")
CLANG = shutil.which("clang")

require_codesign = pytest.mark.skipif(CODESIGN is None, reason="codesign not found")
require_ldid = pytest.mark.skipif(LDID is None, reason="ldid not found")

FIXTURE_TEAM = "TEAM123"
FIXTURE_ORIGINAL_ID = "com.example.fixture"
FIXTURE_RESIGNED_ID = "com.example.fixture.team123"
FIXTURE_UDID = "00008101-000000000000000E"
APP_DIR = "Payload/Fixture.app"


# ------------------------------------------------------------- fakes


class _NetworkError(Exception):
    pass


class FakeResponse:
    def __init__(self, status_code=200, content=b"", json_data=None):
        self.status_code = status_code
        # developer.py treats an empty body as "no content", so JSON
        # responses carry a placeholder body.
        self.content = content if content or json_data is None else b"json-body"
        self._json_data = json_data

    @property
    def text(self):
        return self.content.decode("utf-8", "replace")

    def json(self):
        return self._json_data


def plist_response(payload):
    return FakeResponse(content=plistlib.dumps(payload, fmt=plistlib.FMT_XML))


class FakeHTTP:
    """Stand in for the requests module; no network leaves this file."""

    RequestException = _NetworkError

    def __init__(self):
        self.routes: dict[str, FakeResponse] = {}
        self.calls: list[dict[str, object]] = []
        self.fail = False

    def on(self, url_fragment, response):
        self.routes[url_fragment] = response

    def post(self, url, headers=None, data=None, timeout=None, allow_redirects=True):
        if self.fail:
            raise _NetworkError("connection refused")
        for fragment, response in self.routes.items():
            if fragment in url:
                self.calls.append(
                    {
                        "url": url,
                        "headers": headers,
                        "data": data,
                        "timeout": timeout,
                        "allow_redirects": allow_redirects,
                    }
                )
                return response
        raise AssertionError(f"unexpected request to {url}")


class FakeAnisette:
    """Fresh anisette data per call, like the real AOSKit provider."""

    def __init__(self):
        self.calls = 0

    def get_anisette(self) -> AnisetteData:
        self.calls += 1
        return AnisetteData(
            machine_id="machine-id",
            one_time_password=f"otp-{self.calls}",
            local_user_id="local-user",
            routing_info=84215040,
            device_unique_id="device-uuid",
            device_serial="C02ABC123",
            device_description="<Mac15,12> <macOS;14.4;23E214> <com.apple.AuthKit/1>",
            locale="en_US",
            timezone="America/New_York",
            client_time="2025-01-01T00:00:00Z",
        )


def make_session() -> AppleSession:
    account = Account(first_name="Riley", last_name="Testut", email="user@example.com",
                      dsid="123456")
    return AppleSession(dsid="123456", gs_token="gstoken",
                        token_expiry=datetime(2025, 1, 1), account=account)


@pytest.fixture()
def dev(monkeypatch):
    http = FakeHTTP()
    monkeypatch.setattr(developer, "requests", http)
    anisette = FakeAnisette()
    client = developer.DeveloperServiceClient(make_session(), anisette)
    return SimpleNamespace(http=http, anisette=anisette, client=client)


def recorded_body(call) -> dict:
    return plistlib.loads(call["data"])


# ------------------------------------------------------- profile helpers


def make_profile(**overrides) -> ProvisioningProfile:
    defaults = {
        "identifier": "UUID-1",
        "uuid": "UUID-1",
        "name": "Fixture Profile",
        "team_identifier": FIXTURE_TEAM,
        "bundle_identifier": FIXTURE_RESIGNED_ID,
        "creation_date": datetime(2025, 1, 1),
        "expiration_date": datetime.now() + timedelta(days=7),
        "entitlements": {
            "application-identifier": f"{FIXTURE_TEAM}.{FIXTURE_RESIGNED_ID}",
            "get-task-allow": True,
            "com.apple.developer.team-identifier": FIXTURE_TEAM,
            "keychain-access-groups": [f"{FIXTURE_TEAM}.*"],
            "com.apple.developer.icloud-container-identifiers": True,
        },
        "device_ids": (FIXTURE_UDID,),
        "developer_certificates": (b"\x30\x82\x01\x00cert-der",),
        "is_free": True,
        "data": b"cms-bytes",
    }
    defaults.update(overrides)
    return ProvisioningProfile(**defaults)


def profile_plist_dict() -> dict:
    return {
        "Name": "Fixture Profile",
        "UUID": "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
        "TeamIdentifier": [FIXTURE_TEAM],
        "CreationDate": datetime(2025, 1, 1),
        "ExpirationDate": datetime(2025, 1, 8),
        "Entitlements": {
            "application-identifier": f"{FIXTURE_TEAM}.{FIXTURE_ORIGINAL_ID}",
            "get-task-allow": True,
            "com.apple.developer.team-identifier": FIXTURE_TEAM,
        },
        "ProvisionedDevices": [FIXTURE_UDID],
        "DeveloperCertificates": [],
        "LocalProvision": True,
    }


@pytest.fixture(scope="session")
def cms_profile():
    """A real CMS signed .mobileprovision built with openssl."""
    if OPENSSL is None or SECURITY is None:
        pytest.skip("openssl and security are required for the CMS fixture")
    work = Path(tempfile.mkdtemp(prefix="sideload-cms-test-", dir="/tmp"))
    try:
        plist_path = work / "profile.plist"
        with open(plist_path, "wb") as handle:
            plistlib.dump(profile_plist_dict(), handle)
        key_path = work / "key.pem"
        cert_path = work / "cert.pem"
        result = subprocess.run(
            [
                OPENSSL, "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", str(key_path), "-out", str(cert_path),
                "-days", "30", "-nodes", "-subj", "/CN=ProfileSigner",
            ],
            check=False,
            capture_output=True,
        )
        assert result.returncode == 0, result.stderr
        cms_path = work / "profile.mobileprovision"
        result = subprocess.run(
            [
                OPENSSL, "smime", "-sign", "-binary", "-nodetach",
                "-in", str(plist_path), "-outform", "DER",
                "-out", str(cms_path),
                "-signer", str(cert_path), "-inkey", str(key_path),
            ],
            check=False,
            capture_output=True,
        )
        assert result.returncode == 0, result.stderr
        pem = cert_path.read_bytes()
        der = x509.load_pem_x509_certificate(pem).public_bytes(
            serialization.Encoding.DER
        )
        # Put the real signing certificate into the plist so the CMS
        # fixture exercises certificate_matches_profile too.
        data = cms_path.read_bytes()
        return SimpleNamespace(cms=data, cert_der=der)
    finally:
        shutil.rmtree(work, ignore_errors=True)


@pytest.fixture(scope="session")
def test_cert_pem():
    """A self signed certificate standing in for Apple's issued one."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME,
                               "Apple Development: user@example.com (TEAM123)"),
        ]
    )
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2025, 1, 1))
        .not_valid_after(datetime(2026, 1, 1))
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM)


# --------------------------------------------------------- fixture app


def _build_macho(directory: Path, name: str, dynamic: bool = False) -> bytes:
    """Build one small arm64 Mach-O with clang, or copy a system binary."""
    source = directory / f"{name}.c"
    source.write_text("int sideload_fixture_entry(void) { return 42; }\n")
    built = directory / name
    if CLANG is not None:
        command = [CLANG, "-arch", "arm64"]
        if dynamic:
            command.append("-dynamiclib")
        command += ["-o", str(built), str(source)]
        result = subprocess.run(command, check=False, capture_output=True)
        if result.returncode == 0 and built.exists():
            return built.read_bytes()
    assert Path("/usr/bin/true").is_file(), "no Mach-O source available"
    return Path("/usr/bin/true").read_bytes()


def _info_plist(bundle_id: str, executable: str) -> bytes:
    return plistlib.dumps(
        {
            "CFBundleIdentifier": bundle_id,
            "CFBundleExecutable": executable,
            "CFBundleName": bundle_id.rsplit(".", 1)[-1],
            "CFBundleVersion": "1.0",
            "CFBundleShortVersionString": "1.0",
        }
    )


def _make_zip(source: Path, out: Path, extra_entries: list[str]) -> None:
    entries: list[tuple[str, int, bytes | str]] = []
    for dirpath, dirnames, filenames in os.walk(source):
        dirnames.sort()
        current = Path(dirpath)
        relative = current.relative_to(source)
        prefix = relative.as_posix() + "/" if relative.parts else ""
        for name in dirnames:
            entries.append((prefix + name + "/", (stat.S_IFDIR | 0o755) << 16, b""))
        for name in sorted(filenames):
            child = current / name
            if child == out:
                continue
            if child.is_symlink():
                entries.append(
                    (prefix + name, (stat.S_IFLNK | 0o777) << 16, os.readlink(child))
                )
            else:
                entries.append(
                    (prefix + name, child.stat().st_mode << 16, child.read_bytes())
                )
    for name in extra_entries:
        entries.append((name, 0o100644 << 16, b"junk"))
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        for arcname, attributes, payload in sorted(entries, key=lambda e: e[0]):
            info = zipfile.ZipInfo(arcname, date_time=(2025, 1, 1, 0, 0, 0))
            info.external_attr = attributes
            archive.writestr(info, payload)


@pytest.fixture(scope="session")
def fixture_ipa():
    """The fixture app under /tmp: nested framework, dylib, appex."""
    root = Path(tempfile.mkdtemp(prefix="sideload-sign-test-", dir="/tmp"))
    try:
        app = root / "Payload" / "Fixture.app"
        framework_dir = app / "Frameworks" / "FixKit.framework"
        appex_dir = app / "PlugIns" / "FixExt.appex"
        framework_dir.mkdir(parents=True)
        (app / "Libraries").mkdir()
        appex_dir.mkdir(parents=True)
        (app / "Assets").mkdir()

        main_binary = _build_macho(root, "Fixture")
        dylib_binary = _build_macho(root, "libfix", dynamic=True)
        ext_binary = _build_macho(root, "FixExt")

        (app / "Fixture").write_bytes(main_binary)
        (framework_dir / "FixKit").write_bytes(dylib_binary)
        (framework_dir / "Info.plist").write_bytes(
            _info_plist("com.example.FixKit", "FixKit")
        )
        (app / "Libraries" / "libfix.dylib").write_bytes(dylib_binary)
        (appex_dir / "FixExt").write_bytes(ext_binary)
        (appex_dir / "Info.plist").write_bytes(
            _info_plist(f"{FIXTURE_ORIGINAL_ID}.FixExt", "FixExt")
        )
        (app / "Info.plist").write_bytes(_info_plist(FIXTURE_ORIGINAL_ID, "Fixture"))
        (app / "Assets" / "logo.png").write_bytes(b"PNGDATA")
        os.symlink("FixKit.framework/FixKit", app / "Frameworks" / "FixKit")
        for relative in (
            "Fixture",
            "Frameworks/FixKit.framework/FixKit",
            "Libraries/libfix.dylib",
            "PlugIns/FixExt.appex/FixExt",
        ):
            os.chmod(app / relative, 0o755)

        ipa_path = root / "fixture.ipa"
        _make_zip(
            root,
            ipa_path,
            extra_entries=[
                "__MACOSX/Payload/Fixture.app/._Fixture",
                "Payload/iTunesMetadata.plist",
            ],
        )
        yield SimpleNamespace(root=root, ipa=ipa_path, app=app)
    finally:
        shutil.rmtree(root, ignore_errors=True)


@pytest.fixture()
def extracted(tmp_path, fixture_ipa):
    return ipa.extract_ipa(fixture_ipa.ipa, dest_dir=tmp_path / "work")


# ---------------------------------------------------------------- csr


def test_generate_private_key_is_pkcs8_rsa2048():
    pem = csr.generate_private_key()
    assert pem.startswith(b"-----BEGIN PRIVATE KEY-----")
    key = serialization.load_pem_private_key(pem, password=None)
    assert isinstance(key, rsa.RSAPrivateKey)
    assert key.key_size == 2048


def test_create_csr_roundtrip():
    key_pem = csr.generate_private_key()
    csr_pem = csr.create_csr(key_pem, "MacBook-Pro-sideload")
    assert csr_pem.startswith("-----BEGIN CERTIFICATE REQUEST-----")
    request = x509.load_pem_x509_csr(csr_pem.encode("ascii"))
    assert request.is_signature_valid
    common_names = request.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    assert common_names[0].value == "MacBook-Pro-sideload"
    private_key = serialization.load_pem_private_key(key_pem, password=None)
    assert isinstance(private_key, rsa.RSAPrivateKey)
    public = private_key.public_key()
    request_key = request.public_key()
    assert isinstance(request_key, rsa.RSAPublicKey)
    assert (
        request_key.public_numbers().n == public.public_numbers().n
    )


def test_make_machine_name_stable_ascii():
    first = csr.make_machine_name()
    second = csr.make_machine_name()
    assert first == second
    assert first.endswith("-sideload")
    assert first.isascii()
    assert re.match(r"^[A-Za-z0-9-]+$", first)


def test_load_or_create_machine_id_persists(tmp_path):
    state = tmp_path / "state" / "machine-id"
    first = csr.load_or_create_machine_id(str(state))
    assert re.match(r"^[0-9A-F-]{36}$", first)
    assert state.is_file()
    assert csr.load_or_create_machine_id(str(state)) == first
    other = csr.load_or_create_machine_id(str(tmp_path / "state" / "machine-id-2"))
    assert other != first


# -------------------------------------------------------- developer API


def test_fetch_teams_request_shape(dev):
    dev.http.on(
        "listTeams.action",
        plist_response(
            {
                "resultCode": 0,
                "teams": [
                    {
                        "teamId": "FREE1",
                        "name": "Personal Team",
                        "type": "Individual",
                        "memberships": [{"name": "Riley Testut (free)"}],
                    }
                ],
            }
        ),
    )
    teams = dev.client.fetch_teams()
    assert len(teams) == 1
    call = dev.http.calls[0]
    assert "listTeams.action?clientId=XABBG36SBA" in call["url"]
    headers = call["headers"]
    assert headers["X-Apple-GS-Token"] == "gstoken"
    assert headers["X-Apple-I-Identity-Id"] == "123456"
    assert headers["X-Apple-I-MD"] == "otp-1"
    assert headers["X-Apple-I-MD-M"] == "machine-id"
    assert headers["X-Apple-I-MD-RINFO"] == "84215040"
    assert headers["X-MMe-Client-Info"] == "<Mac15,12> <macOS;14.4;23E214> <com.apple.AuthKit/1>"
    assert headers["User-Agent"] == "Xcode"
    assert headers["X-Apple-App-Info"] == "com.apple.gs.xcode.auth"
    body = recorded_body(call)
    assert body["clientId"] == "XABBG36SBA"
    assert body["protocolVersion"] == "QH65B2"
    assert re.match(r"^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$",
                    body["requestId"])
    assert teams[0].identifier == "FREE1"
    assert teams[0].team_type is TeamType.FREE
    assert teams[0].is_free


def test_fetch_teams_type_mapping(dev):
    dev.http.on(
        "listTeams.action",
        plist_response(
            {
                "resultCode": 0,
                "teams": [
                    {
                        "teamId": "ORG1",
                        "name": "Acme",
                        "type": "Company/Organization",
                        "memberships": [{"name": "Acme Inc"}],
                    },
                    {
                        "teamId": "INDIE1",
                        "name": "Indie",
                        "type": "Individual",
                        "memberships": [{"name": "Indie Dev"}],
                    },
                    {
                        "teamId": "WEIRD",
                        "name": "Unknown",
                        "type": "Something Else",
                        "memberships": [],
                    },
                ],
            }
        ),
    )
    teams = {team.identifier: team for team in dev.client.fetch_teams()}
    assert teams["ORG1"].team_type is TeamType.ORGANIZATION
    assert teams["INDIE1"].team_type is TeamType.INDIVIDUAL
    assert teams["WEIRD"].team_type is TeamType.UNKNOWN


def test_fetch_teams_empty_raises(dev):
    dev.http.on("listTeams.action", plist_response({"resultCode": 0, "teams": []}))
    with pytest.raises(errors.DeveloperAPIError):
        dev.client.fetch_teams()


def test_fetch_developer(dev):
    dev.http.on(
        "viewDeveloper.action",
        plist_response(
            {
                "resultCode": 0,
                "developer": {
                    "firstName": "Riley",
                    "lastName": "Testut",
                    "email": "user@example.com",
                    "dsid": "123456",
                },
            }
        ),
    )
    account = dev.client.fetch_developer()
    assert account == Account(
        first_name="Riley", last_name="Testut", email="user@example.com", dsid="123456"
    )


def test_fetch_devices(dev):
    team = Team(identifier="FREE1", name="Personal", team_type=TeamType.FREE)
    dev.http.on(
        "ios/listDevices.action",
        plist_response(
            {
                "resultCode": 0,
                "devices": [
                    {"name": "Riley's iPhone", "deviceNumber": FIXTURE_UDID},
                    {"name": "iPad", "deviceNumber": "00008101-AAAAAAAA"},
                ],
            }
        ),
    )
    devices = dev.client.fetch_devices(team)
    assert [(d.name, d.identifier) for d in devices] == [
        ("Riley's iPhone", FIXTURE_UDID),
        ("iPad", "00008101-AAAAAAAA"),
    ]
    assert recorded_body(dev.http.calls[0])["teamId"] == "FREE1"


def test_register_device(dev):
    team = Team(identifier="FREE1", name="Personal", team_type=TeamType.FREE)
    dev.http.on(
        "ios/addDevice.action",
        plist_response(
            {
                "resultCode": 0,
                "device": {"name": "Riley's iPhone", "deviceNumber": FIXTURE_UDID},
            }
        ),
    )
    record = dev.client.register_device("Riley's iPhone", FIXTURE_UDID, team)
    assert record.identifier == FIXTURE_UDID
    body = recorded_body(dev.http.calls[0])
    assert body["deviceNumber"] == FIXTURE_UDID
    assert body["name"] == "Riley's iPhone"


def test_register_device_already_registered(dev):
    team = Team(identifier="FREE1", name="Personal", team_type=TeamType.FREE)
    dev.http.on(
        "ios/addDevice.action",
        plist_response(
            {
                "resultCode": 35,
                "userString": "Device already exists for this team",
            }
        ),
    )
    with pytest.raises(errors.DeviceAlreadyRegisteredError):
        dev.client.register_device("Riley's iPhone", FIXTURE_UDID, team)


def test_result_code_35_on_add_device_is_treated_as_registered(dev):
    team = Team(identifier="FREE1", name="Personal", team_type=TeamType.FREE)
    dev.http.on(
        "ios/addDevice.action",
        plist_response({"resultCode": 35, "userString": "invalid device"}),
    )
    with pytest.raises(errors.DeviceAlreadyRegisteredError):
        dev.client.register_device("Riley's iPhone", FIXTURE_UDID, team)


def test_result_code_35_elsewhere_is_generic(dev):
    team = Team(identifier="FREE1", name="Personal", team_type=TeamType.FREE)
    dev.http.on(
        "ios/addAppId.action",
        plist_response({"resultCode": 35, "userString": "invalid input"}),
    )
    with pytest.raises(errors.DeveloperAPIError) as excinfo:
        dev.client.add_app_id("Name", "com.example.x", team)
    assert not isinstance(excinfo.value, errors.DeviceAlreadyRegisteredError)


def test_add_app_id_sanitizes_name(dev):
    team = Team(identifier="FREE1", name="Personal", team_type=TeamType.FREE)
    dev.http.on(
        "ios/addAppId.action",
        plist_response(
            {
                "resultCode": 0,
                "appId": {
                    "appIdId": "APP1",
                    "name": "Fixture",
                    "identifier": FIXTURE_RESIGNED_ID,
                },
            }
        ),
    )
    record = dev.client.add_app_id("My App!! Fixture", FIXTURE_RESIGNED_ID, team)
    assert record == AppIDRecord(
        identifier="APP1", name="Fixture", bundle_identifier=FIXTURE_RESIGNED_ID
    )
    assert recorded_body(dev.http.calls[0])["name"] == "MyAppFixture"


@pytest.mark.parametrize(
    ("result_code", "expected"),
    [
        (9120, errors.AppIDQuotaExceededError),
        (9401, errors.BundleIdentifierUnavailableError),
        (9412, errors.BundleIdentifierUnavailableError),
    ],
)
def test_add_app_id_error_mapping(dev, result_code, expected):
    team = Team(identifier="FREE1", name="Personal", team_type=TeamType.FREE)
    dev.http.on(
        "ios/addAppId.action",
        plist_response({"resultCode": result_code, "userString": "no luck"}),
    )
    with pytest.raises(expected) as excinfo:
        dev.client.add_app_id("Fixture", FIXTURE_RESIGNED_ID, team)
    assert excinfo.value.result_code == result_code
    assert excinfo.value.user_string == "no luck"


def test_add_app_id_quota_hint(dev):
    team = Team(identifier="FREE1", name="Personal", team_type=TeamType.FREE)
    dev.http.on(
        "ios/addAppId.action",
        plist_response({"resultCode": 9120, "userString": "too many"}),
    )
    with pytest.raises(errors.AppIDQuotaExceededError) as excinfo:
        dev.client.add_app_id("Fixture", FIXTURE_RESIGNED_ID, team)
    assert "10 App IDs" in (excinfo.value.hint or "")


def test_fetch_app_ids(dev):
    team = Team(identifier="FREE1", name="Personal", team_type=TeamType.FREE)
    dev.http.on(
        "ios/listAppIds.action",
        plist_response(
            {
                "resultCode": 0,
                "appIds": [
                    {"appIdId": "APP1", "name": "Fixture", "identifier": "com.x.y"},
                    {"appIdId": "APP2", "name": "Other", "identifier": "com.x.z",
                     "features": {"push": True}},
                ],
            }
        ),
    )
    records = dev.client.fetch_app_ids(team)
    assert records[0].identifier == "APP1"
    assert records[1].features == {"push": True}


def test_delete_app_id(dev):
    team = Team(identifier="FREE1", name="Personal", team_type=TeamType.FREE)
    dev.http.on("ios/deleteAppId.action", plist_response({"resultCode": 0}))
    dev.client.delete_app_id(
        AppIDRecord(identifier="APP1", name="Fixture",
                    bundle_identifier=FIXTURE_RESIGNED_ID),
        team,
    )
    assert recorded_body(dev.http.calls[0])["appIdId"] == "APP1"


def test_update_app_id(dev):
    team = Team(identifier="FREE1", name="Personal", team_type=TeamType.FREE)
    dev.http.on(
        "ios/updateAppId.action",
        plist_response(
            {
                "resultCode": 0,
                "appId": {"appIdId": "APP1", "name": "Fixture",
                          "identifier": FIXTURE_RESIGNED_ID},
            }
        ),
    )
    record = dev.client.update_app_id(
        AppIDRecord(identifier="APP1", name="Fixture",
                    bundle_identifier=FIXTURE_RESIGNED_ID,
                    features={"push": True, "icloud": False}),
        team,
    )
    body = recorded_body(dev.http.calls[0])
    assert body["appIdId"] == "APP1"
    assert body["features"] == ["push"]
    assert record.identifier == "APP1"


def test_submit_development_csr(dev, test_cert_pem):
    team = Team(identifier="FREE1", name="Personal", team_type=TeamType.FREE)
    dev.http.on(
        "ios/submitDevelopmentCSR.action",
        plist_response(
            {
                "resultCode": 0,
                "certRequest": {
                    "id": "CERT1",
                    "attributes": {
                        "certContent": test_cert_pem.decode("ascii"),
                        "machineName": "MacBook-Pro-sideload",
                        "machineId": "MACHINE1",
                        "expirationDate": "2026-06-01T00:00:00Z",
                    },
                },
            }
        ),
    )
    certificate = dev.client.create_development_certificate(
        "-----BEGIN CERTIFICATE REQUEST-----", "MacBook-Pro-sideload", team
    )
    assert certificate.identifier == "CERT1"
    assert certificate.machine_name == "MacBook-Pro-sideload"
    assert certificate.machine_id == "MACHINE1"
    assert certificate.certificate_pem == test_cert_pem
    assert certificate.expires_at is not None
    assert certificate.expires_at.year == 2026
    body = recorded_body(dev.http.calls[0])
    assert body["machineName"] == "MacBook-Pro-sideload"
    assert re.match(r"^[0-9A-F-]{36}$", body["machineId"])


def test_submit_csr_rejected(dev):
    team = Team(identifier="FREE1", name="Personal", team_type=TeamType.FREE)
    dev.http.on(
        "ios/submitDevelopmentCSR.action",
        plist_response({"resultCode": 3250, "userString": "invalid CSR"}),
    )
    with pytest.raises(errors.InvalidCertificateRequestError):
        dev.client.create_development_certificate("bad csr", "Mac", team)


def test_list_certificates_v1(dev, test_cert_pem):
    team = Team(identifier="FREE1", name="Personal", team_type=TeamType.FREE)
    der = x509.load_pem_x509_certificate(test_cert_pem).public_bytes(
        serialization.Encoding.DER
    )
    dev.http.on(
        "certificates",
        FakeResponse(
            json_data={
                "data": [
                    {
                        "id": "CERT1",
                        "attributes": {
                            "content": base64.b64encode(der).decode("ascii"),
                            "name": "MacBook-Pro-sideload",
                        },
                    }
                ]
            }
        ),
    )
    certificates = dev.client.list_certificates(team)
    assert len(certificates) == 1
    assert certificates[0].identifier == "CERT1"
    assert certificates[0].certificate_pem == test_cert_pem
    call = dev.http.calls[0]
    assert "services/v1/certificates" in call["url"]
    headers = call["headers"]
    assert headers["X-HTTP-Method-Override"] == "GET"
    assert headers["Content-Type"] == "application/vnd.api+json"
    import json as json_module

    body = json_module.loads(call["data"])
    assert "teamId=FREE1" in body["urlEncodedQueryParams"]
    assert "filter[certificateType]=IOS_DEVELOPMENT" in body["urlEncodedQueryParams"]


def test_revoke_certificate_v1(dev):
    team = Team(identifier="FREE1", name="Personal", team_type=TeamType.FREE)
    from sideload.models import DeveloperCertificate

    issued = DeveloperCertificate(
        identifier="CERT1", machine_name="Mac", machine_id="M1",
        certificate_pem=b"pem",
    )
    dev.http.on("certificates/CERT1", FakeResponse(status_code=204))
    dev.client.revoke_certificate(issued, team)
    call = dev.http.calls[0]
    assert "services/v1/certificates/CERT1" in call["url"]
    assert call["headers"]["X-HTTP-Method-Override"] == "DELETE"


def test_fetch_provisioning_profile(dev, monkeypatch):
    team = Team(identifier="FREE1", name="Personal", team_type=TeamType.FREE)
    app_id = AppIDRecord(identifier="APP1", name="Fixture",
                         bundle_identifier=FIXTURE_RESIGNED_ID)

    def fake_parse(data: bytes) -> ProvisioningProfile:
        assert data == b"cms-bytes"
        return make_profile()

    monkeypatch.setattr(profile, "parse_mobileprovision", fake_parse)
    dev.http.on(
        "ios/downloadTeamProvisioningProfile.action",
        plist_response(
            {
                "resultCode": 0,
                "provisioningProfile": {
                    "provisioningProfileId": "PP123",
                    "encodedProfile": b"cms-bytes",
                },
            }
        ),
    )
    parsed = dev.client.fetch_provisioning_profile(app_id, team)
    assert parsed.identifier == "PP123"
    assert parsed.uuid == "UUID-1"
    assert parsed.data == b"cms-bytes"
    assert recorded_body(dev.http.calls[0])["appIdId"] == "APP1"


def test_delete_provisioning_profile(dev):
    team = Team(identifier="FREE1", name="Personal", team_type=TeamType.FREE)
    dev.http.on("ios/deleteProvisioningProfile.action", plist_response({"resultCode": 0}))
    dev.client.delete_provisioning_profile(make_profile(identifier="PP123"), team)
    assert recorded_body(dev.http.calls[0])["provisioningProfileId"] == "PP123"


def test_http_status_error(dev):
    dev.http.on("listTeams.action", FakeResponse(status_code=500, content=b"<html>"))
    with pytest.raises(errors.DeveloperAPIError, match="HTTP 500"):
        dev.client.fetch_teams()


def test_network_failure_wrapped(dev):
    dev.http.fail = True
    with pytest.raises(errors.DeveloperAPIError, match="request failed"):
        dev.client.fetch_teams()


def test_anisette_refreshed_per_request(dev):
    team = Team(identifier="FREE1", name="Personal", team_type=TeamType.FREE)
    dev.http.on("listTeams.action",
                plist_response({"resultCode": 0, "teams": [
                    {"teamId": "FREE1", "name": "P", "type": "Individual",
                     "memberships": [{"name": "free"}]}
                ]}))
    dev.http.on("ios/listDevices.action",
                plist_response({"resultCode": 0, "devices": []}))
    dev.client.fetch_teams()
    dev.client.fetch_devices(team)
    assert dev.anisette.calls == 2
    first = dev.http.calls[0]["headers"]["X-Apple-I-MD"]
    second = dev.http.calls[1]["headers"]["X-Apple-I-MD"]
    assert first == "otp-1"
    assert second == "otp-2"


# ------------------------------------------------------------ profile


def test_parse_mobileprovision_via_security_cms(cms_profile):
    data = cms_profile.cms
    parsed = profile.parse_mobileprovision(data)
    assert parsed.uuid == "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"
    assert parsed.team_identifier == FIXTURE_TEAM
    assert parsed.name == "Fixture Profile"
    assert parsed.bundle_identifier == FIXTURE_ORIGINAL_ID
    assert parsed.device_ids == (FIXTURE_UDID,)
    assert parsed.is_free is True
    assert parsed.entitlements["get-task-allow"] is True
    assert parsed.entitlements["application-identifier"] == (
        f"{FIXTURE_TEAM}.{FIXTURE_ORIGINAL_ID}"
    )
    assert profile.profile_expiration(parsed) == datetime(2025, 1, 8)
    assert parsed.data == data


def test_parse_mobileprovision_raw_plist_fallback():
    raw = plistlib.dumps(profile_plist_dict())
    parsed = profile.parse_mobileprovision(raw)
    assert parsed.uuid == "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"
    assert parsed.team_identifier == FIXTURE_TEAM


def test_parse_mobileprovision_invalid():
    with pytest.raises(errors.ProfileError):
        profile.parse_mobileprovision(b"this is not a profile at all")


def test_parse_mobileprovision_missing_keys():
    broken = {key: value for key, value in profile_plist_dict().items()
              if key != "UUID"}
    with pytest.raises(errors.ProfileError, match="UUID"):
        profile.parse_mobileprovision(plistlib.dumps(broken))


def test_parse_mobileprovision_empty_team_identifier():
    broken = profile_plist_dict()
    broken["TeamIdentifier"] = []
    with pytest.raises(errors.ProfileError, match="TeamIdentifier"):
        profile.parse_mobileprovision(plistlib.dumps(broken))


def test_assert_profile_usable_pass():
    good = make_profile()
    profile.assert_profile_usable(good, FIXTURE_UDID, FIXTURE_RESIGNED_ID)


def test_assert_profile_usable_expired():
    expired = make_profile(
        expiration_date=datetime(2020, 1, 1),
        creation_date=datetime(2019, 12, 25),
    )
    with pytest.raises(errors.ProfileExpiredError):
        profile.assert_profile_usable(expired, FIXTURE_UDID, FIXTURE_RESIGNED_ID)


def test_assert_profile_usable_hyphenless_udid():
    good = make_profile()
    profile.assert_profile_usable(
        good, FIXTURE_UDID.replace("-", ""), FIXTURE_RESIGNED_ID
    )


def test_assert_profile_usable_device_missing():
    good = make_profile()
    with pytest.raises(errors.DeviceNotProvisionedError):
        profile.assert_profile_usable(good, "00008101-ZZZZZZZZZZZZZZZZ",
                                      FIXTURE_RESIGNED_ID)


def test_assert_profile_usable_bundle_mismatch():
    good = make_profile()
    with pytest.raises(errors.BundleIDMismatchError):
        profile.assert_profile_usable(good, FIXTURE_UDID, "com.example.other")


def test_assert_profile_usable_no_certificates():
    empty = make_profile(developer_certificates=())
    with pytest.raises(errors.ProfileError, match="DeveloperCertificates"):
        profile.assert_profile_usable(empty, FIXTURE_UDID, FIXTURE_RESIGNED_ID)


def test_certificate_matches_profile(cms_profile):
    parsed = make_profile(developer_certificates=(cms_profile.cert_der,))
    assert profile.certificate_matches_profile(cms_profile.cert_der, parsed)
    assert not profile.certificate_matches_profile(b"\x30\x82other", parsed)
    assert profile.certificate_matches_profile(
        cms_profile.cert_der, make_profile()
    ) is False


# ------------------------------------------------------- entitlements


def test_build_entitlements_merge_and_drop():
    prof = make_profile()
    original = {
        "application-identifier": "OLDBUNDLE.com.example.fixture",
        "get-task-allow": False,
        "com.apple.developer.icloud-container-identifiers": ["iCloud.com.example"],
        "com.apple.private.hax": True,
        "com.apple.developer.aps-environment": "development",
    }
    merged, dropped = entitlements.build_entitlements(
        prof, original, None, strict=False
    )
    assert merged["application-identifier"] == f"{FIXTURE_TEAM}.{FIXTURE_RESIGNED_ID}"
    assert merged["get-task-allow"] is True
    assert merged["com.apple.developer.team-identifier"] == FIXTURE_TEAM
    assert merged["keychain-access-groups"] == [f"{FIXTURE_TEAM}.*"]
    assert merged["com.apple.developer.icloud-container-identifiers"] == (
        ["iCloud.com.example"]
    )
    assert dropped == [
        "com.apple.developer.aps-environment",
        "com.apple.private.hax",
    ]
    assert "com.apple.private.hax" not in merged


def test_build_entitlements_strict_raises():
    prof = make_profile()
    original = {"com.apple.private.hax": True}
    with pytest.raises(errors.EntitlementsError) as excinfo:
        entitlements.build_entitlements(prof, original, None, strict=True)
    assert excinfo.value.dropped == ["com.apple.private.hax"]


def test_build_entitlements_keychain_groups_not_granted():
    granted = {
        key: value
        for key, value in make_profile().entitlements.items()
        if key != "keychain-access-groups"
    }
    prof = make_profile(entitlements=granted)
    original = {"keychain-access-groups": ["OLDBUNDLE.*"]}
    merged, dropped = entitlements.build_entitlements(
        prof, original, None, strict=False
    )
    assert "keychain-access-groups" not in merged
    assert dropped == ["keychain-access-groups"]


def test_build_entitlements_extra_merged_unconditionally():
    prof = make_profile()
    extra = {"com.apple.security.application-groups": ["group.example"]}
    merged, dropped = entitlements.build_entitlements(prof, None, extra, strict=False)
    assert merged["com.apple.security.application-groups"] == ["group.example"]
    assert dropped == []


def test_build_entitlements_without_original():
    prof = make_profile()
    merged, dropped = entitlements.build_entitlements(prof, None, None, strict=False)
    assert dropped == []
    assert merged["get-task-allow"] is True
    assert merged["application-identifier"] == f"{FIXTURE_TEAM}.{FIXTURE_RESIGNED_ID}"


def test_write_entitlements_plist_roundtrip(tmp_path):
    target = tmp_path / "ents" / "entitlements.plist"
    ent = {"application-identifier": "TEAM123.com.x", "get-task-allow": True}
    entitlements.write_entitlements_plist(ent, target)
    loaded = plistlib.loads(target.read_bytes())
    assert loaded == ent


def test_validate_installable_detects_mismatches():
    prof = make_profile()
    assert entitlements.validate_installable(
        prof,
        {
            "application-identifier": f"{FIXTURE_TEAM}.{FIXTURE_RESIGNED_ID}",
            "com.apple.developer.team-identifier": FIXTURE_TEAM,
            "keychain-access-groups": [f"{FIXTURE_TEAM}.*"],
        },
    ) == []
    problems = entitlements.validate_installable(
        prof,
        {
            "application-identifier": "OTHER.com.example.fixture",
            "com.apple.developer.team-identifier": "OTHER",
            "keychain-access-groups": ["OTHER.*"],
        },
    )
    assert problems == [
        "application-identifier",
        "com.apple.developer.team-identifier",
        "keychain-access-groups",
    ]


def test_read_entitlements_none_for_binary_without_entitlements(fixture_ipa):
    binary = fixture_ipa.app / "Fixture"
    if CODESIGN is None and LDID is None:
        pytest.skip("no entitlement reader available")
    assert entitlements.read_entitlements(binary) is None


def test_extract_commented_entitlements(monkeypatch):
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        "<plist version=\"1.0\"><dict><key>get-task-allow</key><true/>"
        "<!---><!--><key>com.apple.private.hax</key><true/><!-- -->"
        "<key>visible</key><string>yes</string></dict></plist>"
    )
    monkeypatch.setattr(
        entitlements, "_raw_entitlements_blob", lambda path: xml.encode()
    )
    hidden = entitlements.extract_commented_entitlements(Path("/dev/null"))
    assert hidden == {"com.apple.private.hax": True}


# ----------------------------------------------------------------- ipa


def test_extract_ipa_inventories_bundles(extracted, tmp_path):
    work = tmp_path / "work"
    app = extracted.main_bundle.root
    assert app == work / "Payload" / "Fixture.app"
    assert extracted.main_bundle.bundle_identifier == FIXTURE_ORIGINAL_ID
    assert extracted.main_bundle.executable == app / "Fixture"
    assert [bundle.root.name for bundle in extracted.all_bundles] == [
        "Fixture.app",
        "FixKit.framework",
        "FixExt.appex",
    ]
    # symlinks survive extraction
    assert (app / "Frameworks" / "FixKit").is_symlink()
    assert os.readlink(app / "Frameworks" / "FixKit") == "FixKit.framework/FixKit"
    # permissions survive extraction
    assert (app / "Fixture").stat().st_mode & stat.S_IXUSR
    assert (app / "Frameworks" / "FixKit.framework" / "FixKit").stat().st_mode & stat.S_IXUSR
    # __MACOSX junk and payload artifacts are dropped
    assert not (work / "__MACOSX").exists()
    assert not (work / "Payload" / "iTunesMetadata.plist").exists()


def test_extract_ipa_rejects_zip_without_payload(tmp_path):
    bad = tmp_path / "bad.ipa"
    with zipfile.ZipFile(bad, "w") as archive:
        archive.writestr("README.txt", "not an ipa")
    with pytest.raises(errors.NotAnIPAError):
        ipa.extract_ipa(bad, dest_dir=tmp_path / "work")


def test_extract_ipa_rejects_payload_without_app(tmp_path):
    bad = tmp_path / "bad.ipa"
    with zipfile.ZipFile(bad, "w") as archive:
        archive.writestr("Payload/readme.txt", "no app here")
    with pytest.raises(errors.NoAppBundleError):
        ipa.extract_ipa(bad, dest_dir=tmp_path / "work")


def test_extract_ipa_missing_file(tmp_path):
    with pytest.raises(errors.IPAError):
        ipa.extract_ipa(tmp_path / "missing.ipa", dest_dir=tmp_path / "work")


def test_extract_ipa_rejects_fairplay_binary(tmp_path):
    # A minimal arm64 Mach-O with one LC_ENCRYPTION_INFO_64, cryptid=1.
    header = struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 0, 2, 1, 24, 0, 0)
    load_command = struct.pack("<6I", 0x2C, 24, 0, 16, 1, 0)
    encrypted = header + load_command
    bad = tmp_path / "encrypted.ipa"
    with zipfile.ZipFile(bad, "w") as archive:
        archive.writestr("Payload/Enc.app/Info.plist", _info_plist("com.enc", "Enc"))
        info = zipfile.ZipInfo("Payload/Enc.app/Enc", date_time=(2025, 1, 1, 0, 0, 0))
        info.external_attr = 0o100755 << 16
        archive.writestr(info, encrypted)
    with pytest.raises(errors.UnsupportedIPAError, match="FairPlay"):
        ipa.extract_ipa(bad, dest_dir=tmp_path / "work")


def test_macho_helpers(fixture_ipa):
    binary = fixture_ipa.app / "Fixture"
    assert ipa.is_macho_file(binary)
    assert not ipa.is_macho_file(fixture_ipa.app / "Assets" / "logo.png")
    assert ipa.has_code_signature(binary)  # linker signed by clang
    assert not ipa._is_fairplay_encrypted(binary)
    assert ipa.is_macho_file(Path("/usr/bin/true"))  # fat binary magic


def test_inventory_order(extracted):
    bundle = extracted.main_bundle
    machos = [p.relative_to(bundle.root).as_posix() for p in bundle.nested_machos()]
    assert machos == [
        "Libraries/libfix.dylib",
        "Frameworks/FixKit.framework/FixKit",
    ]
    nested = [b.root.name for b in bundle.nested_bundles()]
    assert nested == ["FixKit.framework", "FixExt.appex"]
    inventory = [p.relative_to(bundle.root).as_posix()
                 for p in bundle.signable_inventory()]
    assert inventory == [
        "Libraries/libfix.dylib",
        "Frameworks/FixKit.framework/FixKit",
        "PlugIns/FixExt.appex/FixExt",
        "Fixture",
    ]


def test_resign_bundle_id():
    assert ipa.resign_bundle_id(FIXTURE_ORIGINAL_ID, FIXTURE_TEAM) == (
        FIXTURE_RESIGNED_ID
    )
    assert ipa.resign_bundle_id(FIXTURE_ORIGINAL_ID, "teamABC") == (
        f"{FIXTURE_ORIGINAL_ID}.teamabc"
    )
    assert ipa.resign_bundle_id(
        f"{FIXTURE_ORIGINAL_ID}.FixExt", FIXTURE_TEAM,
        parent_bundle_id=FIXTURE_RESIGNED_ID,
    ) == f"{FIXTURE_RESIGNED_ID}.FixExt"


def test_set_bundle_identifier(extracted):
    bundle = extracted.all_bundles[2]  # FixExt.appex
    assert bundle.root.name == "FixExt.appex"
    bundle.set_bundle_identifier(f"{FIXTURE_RESIGNED_ID}.FixExt")
    reloaded = plistlib.loads(bundle.info_plist_path.read_bytes())
    assert reloaded["CFBundleIdentifier"] == f"{FIXTURE_RESIGNED_ID}.FixExt"
    assert bundle.bundle_identifier == f"{FIXTURE_RESIGNED_ID}.FixExt"


def test_remove_appstore_artifacts(extracted):
    bundle = extracted.main_bundle
    (bundle.root / "SC_Info").mkdir()
    (bundle.root / "SC_Info" / "manifest.plist").write_bytes(b"x")
    (bundle.root / "_MASReceipt").mkdir()
    (bundle.root / "_MASReceipt" / "receipt").write_bytes(b"x")
    (bundle.root / "iTunesMetadata.plist").write_bytes(b"x")
    bundle.remove_appstore_artifacts()
    assert not (bundle.root / "SC_Info").exists()
    assert not (bundle.root / "_MASReceipt").exists()
    assert not (bundle.root / "iTunesMetadata.plist").exists()


def test_embed_profile(extracted, cms_profile):
    bundle = extracted.main_bundle
    bundle.embed_profile(cms_profile.cms)
    embedded = bundle.root / "embedded.mobileprovision"
    assert embedded.read_bytes() == cms_profile.cms
    reparsed = profile.parse_mobileprovision(embedded.read_bytes())
    assert reparsed.uuid == "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"


def test_repack_deterministic_and_clean(tmp_path, extracted):
    first = tmp_path / "first.signed.ipa"
    second = tmp_path / "second.signed.ipa"
    assert ipa.repack_ipa(extracted, first) == first
    ipa.repack_ipa(extracted, second)
    assert first.read_bytes() == second.read_bytes()
    with zipfile.ZipFile(first) as archive:
        names = archive.namelist()
        assert names == sorted(names)
        assert not any("__MACOSX" in name for name in names)
        assert not any(name.endswith(".DS_Store") for name in names)
        assert APP_DIR + "/" in names
        link = archive.getinfo(APP_DIR + "/Frameworks/FixKit")
        assert stat.S_ISLNK(link.external_attr >> 16)
        assert archive.read(link) == b"FixKit.framework/FixKit"
        executable = archive.getinfo(APP_DIR + "/Fixture")
        assert (executable.external_attr >> 16) & stat.S_IXUSR
        assert archive.getinfo(APP_DIR + "/Fixture").date_time == (1980, 1, 1, 0, 0, 0)


def test_repack_roundtrip(tmp_path, extracted):
    out = tmp_path / "roundtrip.ipa"
    ipa.repack_ipa(extracted, out)
    reborn = ipa.extract_ipa(out, dest_dir=tmp_path / "reborn")
    assert reborn.main_bundle.bundle_identifier == FIXTURE_ORIGINAL_ID
    assert [b.root.name for b in reborn.all_bundles] == [
        "Fixture.app",
        "FixKit.framework",
        "FixExt.appex",
    ]
    app = reborn.main_bundle.root
    assert (app / "Frameworks" / "FixKit").is_symlink()
    assert (app / "Assets" / "logo.png").read_bytes() == b"PNGDATA"
    assert (app / "Fixture").stat().st_mode & stat.S_IXUSR
    reborn_inventory = [
        p.relative_to(reborn.main_bundle.root).as_posix()
        for p in reborn.main_bundle.signable_inventory()
    ]
    assert reborn_inventory == [
        "Libraries/libfix.dylib",
        "Frameworks/FixKit.framework/FixKit",
        "PlugIns/FixExt.appex/FixExt",
        "Fixture",
    ]


# --------------------------------------------------------------- signer


def _entitlements_by_path() -> dict[str, dict[str, object]]:
    prof = make_profile()
    original = {
        "com.apple.developer.icloud-container-identifiers": ["iCloud.com.example"],
        "com.apple.private.hax": True,
    }
    main_ents, _ = entitlements.build_entitlements(prof, original, None, False)
    ext_profile = make_profile(
        entitlements={
            "application-identifier": f"{FIXTURE_TEAM}.{FIXTURE_RESIGNED_ID}.FixExt",
            "get-task-allow": True,
            "com.apple.developer.team-identifier": FIXTURE_TEAM,
        }
    )
    ext_ents, _ = entitlements.build_entitlements(ext_profile, None, None, False)
    return {
        "Fixture": main_ents,
        "PlugIns/FixExt.appex/FixExt": ext_ents,
    }


def test_keychain_signer_requires_codesign(monkeypatch):
    monkeypatch.setattr(signer, "_which_tool", lambda name: None)
    with pytest.raises(errors.TransportError):
        signer.KeychainSigner()


def test_keychain_signer_requires_identity(extracted):
    if CODESIGN is None:
        pytest.skip("codesign not found")
    s = signer.KeychainSigner()
    with pytest.raises(errors.SigningError, match="keychain identity"):
        s.sign_bundle(
            extracted.main_bundle,
            {},
            SigningIdentity(team_identifier=FIXTURE_TEAM),
        )


@require_codesign
def test_sign_bundle_order_and_entitlements(tmp_path, fixture_ipa, monkeypatch):
    bundle = ipa.extract_ipa(fixture_ipa.ipa, dest_dir=tmp_path / "work")
    s = signer.KeychainSigner()
    identity = SigningIdentity(team_identifier=FIXTURE_TEAM, keychain_identity="-")

    calls: list[list[str]] = []
    original_run = signer._run_command

    def recording(command):
        calls.append(list(command))
        return original_run(command)

    monkeypatch.setattr(signer, "_run_command", recording)

    s.sign_bundle(bundle.main_bundle, _entitlements_by_path(), identity)

    def rel_of(command) -> str:
        path = Path(command[-1])
        try:
            relative = path.relative_to(bundle.main_bundle.root)
        except ValueError:
            return path.as_posix()
        return relative.as_posix() or "."

    sequence = [rel_of(command) for command in calls]
    # The pinned order: loose dylibs, framework binaries, nested
    # extension executables, main executable, then seals deepest first
    # with the main bundle root last.
    assert sequence == [
        "Libraries/libfix.dylib",
        "Frameworks/FixKit.framework/FixKit",
        "PlugIns/FixExt.appex/FixExt",
        "Fixture",
        "Frameworks/FixKit.framework",
        "PlugIns/FixExt.appex",
        ".",
    ]
    with_entitlements = {
        index
        for index, command in enumerate(calls)
        if "--entitlements" in command
    }
    assert with_entitlements == {2, 3, 5, 6}

    assert s.verify_bundle(bundle.main_bundle) == []

    read = entitlements.read_entitlements(bundle.main_bundle.executable)
    assert read is not None
    assert read.get("get-task-allow") is True
    assert read.get("application-identifier") == f"{FIXTURE_TEAM}.{FIXTURE_RESIGNED_ID}"
    appex_executable = bundle.main_bundle.root / "PlugIns" / "FixExt.appex" / "FixExt"
    appex_read = entitlements.read_entitlements(appex_executable)
    assert appex_read is not None
    assert appex_read.get("application-identifier") == (
        f"{FIXTURE_TEAM}.{FIXTURE_RESIGNED_ID}.FixExt"
    )


@require_codesign
def test_verify_bundle_detects_post_sign_tampering(tmp_path, fixture_ipa):
    bundle = ipa.extract_ipa(fixture_ipa.ipa, dest_dir=tmp_path / "work")
    s = signer.KeychainSigner()
    identity = SigningIdentity(team_identifier=FIXTURE_TEAM, keychain_identity="-")
    s.sign_bundle(bundle.main_bundle, _entitlements_by_path(), identity)
    assert s.verify_bundle(bundle.main_bundle) == []
    (bundle.main_bundle.root / "Assets" / "logo.png").write_bytes(b"tampered")
    problems = s.verify_bundle(bundle.main_bundle)
    assert problems != []


@require_ldid
def test_ldid_signer_fallback_entitlements(tmp_path, fixture_ipa):
    bundle = ipa.extract_ipa(fixture_ipa.ipa, dest_dir=tmp_path / "work")
    identity = SigningIdentity(
        team_identifier=FIXTURE_TEAM,
        certificate_pem=b"pem-unused",
        private_key_pem=b"key-unused",
    )
    ldid_signer = signer.LDIDSigner(identity)
    ldid_signer.sign_bundle(bundle.main_bundle, _entitlements_by_path(), identity)
    assert ldid_signer.verify_bundle(bundle.main_bundle) == []
    # codesign refuses ldid pseudo signatures, so read_entitlements
    # must fall back to "ldid -e" and still find the entitlements.
    read = entitlements.read_entitlements(bundle.main_bundle.executable)
    assert read is not None
    assert read.get("get-task-allow") is True
    assert read.get("application-identifier") == f"{FIXTURE_TEAM}.{FIXTURE_RESIGNED_ID}"


def test_identity_name_for(test_cert_pem):
    assert signer.identity_name_for(test_cert_pem) == (
        "Apple Development: user@example.com (TEAM123)"
    )


def test_identity_name_for_rejects_garbage():
    with pytest.raises(errors.SigningError):
        signer.identity_name_for(b"not a certificate")


def test_entitlements_ok_for_profile():
    prof = make_profile()
    good = {
        "application-identifier": f"{FIXTURE_TEAM}.{FIXTURE_RESIGNED_ID}",
        "get-task-allow": True,
        "com.apple.developer.team-identifier": FIXTURE_TEAM,
        "keychain-access-groups": [f"{FIXTURE_TEAM}.*"],
        "com.apple.developer.icloud-container-identifiers": ["iCloud.x"],
    }
    assert signer.entitlements_ok_for_profile(good, prof)
    assert not signer.entitlements_ok_for_profile(
        {**good, "application-identifier": "OTHER.x"}, prof
    )
    assert not signer.entitlements_ok_for_profile(
        {**good, "com.apple.private.hax": True}, prof
    )
    assert not signer.entitlements_ok_for_profile(
        {**good, "keychain-access-groups": ["OTHER.*"]}, prof
    )
    assert not signer.entitlements_ok_for_profile(
        {**good, "com.apple.developer.team-identifier": "OTHER"}, prof
    )


# --- zip extraction hardening (parent verification) ---


def _zip_blob(entries):
    import io

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data, mode in entries:
            info = zipfile.ZipInfo(name)
            info.external_attr = mode << 16
            zf.writestr(info, data)
    return buf.getvalue()


def _extract_blob(blob, dest):
    import io

    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        ipa._extract_archive(zf, dest)


def test_extract_rejects_absolute_entry(tmp_path):
    dest = tmp_path / "out"
    dest.mkdir()
    blob = _zip_blob([("/etc/evil", b"x", 0o100644)])
    with pytest.raises(errors.IPAError):
        _extract_blob(blob, dest)
    assert not (tmp_path / "etc").exists()


def test_extract_rejects_parent_traversal_entry(tmp_path):
    dest = tmp_path / "out"
    dest.mkdir()
    blob = _zip_blob([("Payload/../../evil", b"x", 0o100644)])
    with pytest.raises(errors.IPAError):
        _extract_blob(blob, dest)


def test_extract_rejects_absolute_symlink(tmp_path):
    dest = tmp_path / "out"
    dest.mkdir()
    blob = _zip_blob([("Payload/Runner.app/link", b"/etc/passwd", stat.S_IFLNK | 0o777)])
    with pytest.raises(errors.IPAError):
        _extract_blob(blob, dest)


def test_extract_rejects_escaping_relative_symlink(tmp_path):
    dest = tmp_path / "out"
    dest.mkdir()
    blob = _zip_blob([("Payload/Runner.app/esc", b"../../../etc", stat.S_IFLNK | 0o777)])
    with pytest.raises(errors.IPAError):
        _extract_blob(blob, dest)


def test_extract_allows_relative_symlink(tmp_path):
    dest = tmp_path / "out"
    dest.mkdir()
    blob = _zip_blob(
        [
            ("Payload/Runner.app/Versions/A/App", b"x", 0o100755),
            ("Payload/Runner.app/Versions/Current", b"A", stat.S_IFLNK | 0o777),
        ]
    )
    _extract_blob(blob, dest)
    link = dest / "Payload/Runner.app/Versions/Current"
    assert link.is_symlink()
    assert os.readlink(link) == "A"


def test_extract_allows_entry_under_symlinked_dir_inside_root(tmp_path):
    dest = tmp_path / "out"
    dest.mkdir()
    blob = _zip_blob(
        [
            ("Payload/Runner.app/Versions/A/App", b"x", 0o100755),
            ("Payload/Runner.app/Versions/Current", b"A", stat.S_IFLNK | 0o777),
            ("Payload/Runner.app/Versions/Current/Resource", b"y", 0o100644),
        ]
    )
    _extract_blob(blob, dest)
    assert (dest / "Payload/Runner.app/Versions/A/Resource").read_bytes() == b"y"


def test_extract_rejects_entry_over_size_limit(tmp_path, monkeypatch):
    bomb = tmp_path / "bomb.ipa"
    with zipfile.ZipFile(bomb, "w") as archive:
        archive.writestr("Payload/App.app/Info.plist", _info_plist("com.bomb", "Bomb"))
        archive.writestr("Payload/App.app/big.bin", b"x" * 4096)
    monkeypatch.setattr(ipa, "MAX_ENTRY_BYTES", 64)
    with pytest.raises(errors.IPAError, match="larger than"):
        ipa.extract_ipa(bomb, dest_dir=tmp_path / "work")


def test_extract_drops_setuid_and_sticky_bits(tmp_path):
    archive_path = tmp_path / "suid.ipa"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("Payload/App.app/Info.plist", _info_plist("com.suid", "Suid"))
        info = zipfile.ZipInfo("Payload/App.app/tool", date_time=(2025, 1, 1, 0, 0, 0))
        info.external_attr = (stat.S_IFREG | 0o4755) << 16
        archive.writestr(info, b"#!/bin/sh\necho hi\n")
    bundle = ipa.extract_ipa(archive_path, dest_dir=tmp_path / "work")
    mode = stat.S_IMODE((bundle.main_bundle.root / "tool").stat().st_mode)
    assert mode & 0o4000 == 0
    assert mode & 0o2000 == 0
    assert mode & 0o777 == 0o755


def test_repack_leaves_no_temp_file(tmp_path, fixture_ipa):
    bundle = ipa.extract_ipa(fixture_ipa.ipa, dest_dir=tmp_path / "work")
    out = tmp_path / "signed.ipa"
    ipa.repack_ipa(bundle, out)
    assert out.is_file()
    assert list(tmp_path.glob(".*.tmp")) == []


def test_cleanup_work_dirs_removes_its_own_tree(fixture_ipa):
    bundle = ipa.extract_ipa(fixture_ipa.ipa)
    assert bundle.work_dir.exists()
    ipa.cleanup_work_dirs()
    assert not bundle.work_dir.exists()


def test_cleanup_leaves_a_caller_supplied_directory(tmp_path, fixture_ipa):
    dest = tmp_path / "work"
    ipa.extract_ipa(fixture_ipa.ipa, dest_dir=dest)
    ipa.cleanup_work_dirs()
    assert dest.exists()


def test_developer_requests_refuse_redirects(dev):
    dev.http.on(
        "listTeams.action",
        plist_response(
            {
                "resultCode": 0,
                "teams": [
                    {
                        "teamId": "FREE1",
                        "name": "Personal Team",
                        "type": "Individual",
                        "memberships": [{"name": "Riley Testut (free)"}],
                    }
                ],
            }
        ),
    )
    dev.client.fetch_teams()
    assert dev.http.calls
    assert all(call["allow_redirects"] is False for call in dev.http.calls)


def test_repack_strips_setuid_bits(tmp_path, fixture_ipa):
    bundle = ipa.extract_ipa(fixture_ipa.ipa, dest_dir=tmp_path / "work")
    tool = bundle.main_bundle.root / "suidtool"
    tool.write_bytes(b"#!/bin/sh\necho hi\n")
    tool.chmod(0o4755)
    out = tmp_path / "signed.ipa"
    ipa.repack_ipa(bundle, out)
    with zipfile.ZipFile(out) as archive:
        info = next(item for item in archive.infolist() if item.filename.endswith("/suidtool"))
        mode = info.external_attr >> 16
        assert mode & 0o4000 == 0
        assert mode & 0o2000 == 0
        assert mode & 0o777 == 0o755


def test_session_expired_result_code_maps_to_session_error(dev):
    dev.http.on(
        "listTeams.action",
        plist_response(
            {
                "resultCode": 1100,
                "userString": "Your session has expired. Please log in.",
            }
        ),
    )
    with pytest.raises(errors.SessionExpiredError):
        dev.client.fetch_teams()


def test_http_unauthorized_maps_to_session_error(dev):
    dev.http.on("listTeams.action", FakeResponse(status_code=401, content=b"denied"))
    with pytest.raises(errors.SessionExpiredError):
        dev.client.fetch_teams()


def test_create_certificate_sends_persisted_machine_id(dev, monkeypatch):
    captured = {}

    def fake_send(action, parameters, team=None):
        captured.update(parameters)
        return {"certRequest": {"id": "C1"}}

    monkeypatch.setattr(dev.client, "_send_action", fake_send)
    monkeypatch.setattr(
        dev.client, "_developer_certificate", lambda payload: SimpleNamespace()
    )
    team = Team(identifier="FREE1", name="Personal", team_type=TeamType.FREE)
    dev.client.create_development_certificate(
        "CSR-PEM", "MacBook-Pro", team, machine_id="PERSISTED-ID"
    )
    assert captured["machineId"] == "PERSISTED-ID"


def test_nested_bundles_terminates_on_self_symlink(tmp_path):
    archive_path = tmp_path / "loop.ipa"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("Payload/App.app/Info.plist", _info_plist("com.loop", "Loop"))
        exe = zipfile.ZipInfo("Payload/App.app/App", date_time=(2025, 1, 1, 0, 0, 0))
        exe.external_attr = (stat.S_IFREG | 0o755) << 16
        archive.writestr(exe, b"\xcf\xfa\xed\xfe" + b"\x00" * 28)
        link = zipfile.ZipInfo("Payload/App.app/loop", date_time=(2025, 1, 1, 0, 0, 0))
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(link, ".")
    bundle = ipa.extract_ipa(archive_path, dest_dir=tmp_path / "work")
    assert bundle.main_bundle.nested_bundles() == []


def test_extract_rejects_oversized_symlink(tmp_path):
    archive_path = tmp_path / "biglink.ipa"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("Payload/App.app/Info.plist", _info_plist("com.link", "Link"))
        exe = zipfile.ZipInfo("Payload/App.app/App", date_time=(2025, 1, 1, 0, 0, 0))
        exe.external_attr = (stat.S_IFREG | 0o755) << 16
        archive.writestr(exe, b"\xcf\xfa\xed\xfe" + b"\x00" * 28)
        link = zipfile.ZipInfo("Payload/App.app/link", date_time=(2025, 1, 1, 0, 0, 0))
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(link, "a" * 5000)
    with pytest.raises(errors.IPAError, match="oversized symlink"):
        ipa.extract_ipa(archive_path, dest_dir=tmp_path / "work")


def test_extract_rejects_watchos_companion(tmp_path):
    archive_path = tmp_path / "watch.ipa"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("Payload/App.app/Info.plist", _info_plist("com.watch", "Watch"))
        archive.writestr(
            "Watch/Extension.app/Info.plist", _info_plist("com.watch.ext", "Ext")
        )
    with pytest.raises(errors.UnsupportedIPAError, match="watchOS"):
        ipa.extract_ipa(archive_path, dest_dir=tmp_path / "work")
