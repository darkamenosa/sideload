"""Offline tests for the AUTH slice: anisette, Grand Slam SRP login, 2FA,
error mapping, and the Keychain session store.

No test in this file touches the network, Apple, a real Apple ID, or the
real macOS Keychain. The Grand Slam server is a local mock that
implements the server side of Apple's SRP-6a variant exactly as
corecrypto's ccsrp computes it (validated against ccsrp_client.c and
ccsrp_priv.h), and the Keychain is an in-memory fake of the security
CLI.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import plistlib
import secrets
import shlex
import struct
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import requests
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from sideload.apple import anisette as anisette_module
from sideload.apple import auth as auth_module
from sideload.apple.anisette import (
    CLIENT_INFO_TEMPLATE,
    FALLBACK_DEVICE_SERIAL,
    AnisetteProvider,
)
from sideload.apple.auth import (
    GSA_APP_NAME,
    GSA_ENDPOINT,
    GSA_PROTOCOL_VERSION,
    GSA_TWO_FACTOR_TRIGGER_URL,
    GSA_TWO_FACTOR_VALIDATE_URL,
    MAX_TWO_FACTOR_ATTEMPTS,
    XCODE_USER_AGENT,
    GrandSlamClient,
    build_cpd,
)
from sideload.errors import (
    AnisetteError,
    AuthError,
    KeychainError,
    SideloadError,
    TwoFactorError,
)
from sideload.keychain import SERVICE_SESSION, KeychainStore
from sideload.models import Account, AnisetteData, AppleSession

# The RFC 5054 2048 bit group, the same prime ccsrp_gp_rfc5054_2048 uses.
SRP_N = auth_module._SRP_N
SRP_G = 2
SRP_SIZE = 256

EMAIL = "user@example.com"
PASSWORD = "correct horse battery staple"
ADSID = "1001234567"
IDMS_TOKEN = "idms-token-abc"
GS_TOKEN = "gs-token-xyz"
EXPIRY_MS = 1767139200000


def sha256(*chunks: bytes) -> bytes:
    digest = hashlib.sha256()
    for chunk in chunks:
        digest.update(chunk)
    return digest.digest()


def pad(value: int) -> bytes:
    return value.to_bytes(SRP_SIZE, "big")


# ----------------------------------------------------------- anisette fakes


class FakeAnisetteProvider(AnisetteProvider):
    """Deterministic anisette source; the OTP changes on every call so
    tests can assert that each request fetches a fresh set."""

    def __init__(self) -> None:
        self.calls = 0

    def get_anisette(self) -> AnisetteData:
        self.calls += 1
        return AnisetteData(
            machine_id="machine-id-value",
            one_time_password=f"otp-{self.calls}",
            local_user_id="local-user-value",
            routing_info=84215040,
            device_unique_id="device-udid-value",
            device_serial="C02LKHBBFD57",
            device_description=(
                "<Mac15,12> <macOS;26.0;25A0000> "
                "<com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>"
            ),
            locale="en_US",
            timezone="GMT+7",
            client_time="2026-01-27T10:11:12Z",
        )


# --------------------------------------------------------- mock GSA server


def negotiation_transcript(sp: str, spd: bytes, sc: bytes) -> bytes:
    """The byte stream AltSign feeds its running SHA-256 before checking np."""
    digest = hashlib.sha256()
    digest.update(b"s2k,s2k_fo||")
    digest.update(sp.encode("utf-8"))
    digest.update(b"|")
    digest.update(struct.pack("<I", len(spd)))
    digest.update(spd)
    digest.update(b"|")
    digest.update(struct.pack("<I", len(sc)))
    digest.update(sc)
    digest.update(b"|")
    return digest.digest()


def cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def gcm_encrypt_xyz(sk: bytes, plaintext: bytes) -> bytes:
    """The "XYZ" app token envelope: magic, 16 byte IV, ciphertext, tag."""
    iv = b"\x33" * 16
    encryptor = Cipher(algorithms.AES(sk), modes.GCM(iv)).encryptor()
    encryptor.authenticate_additional_data(b"XYZ")
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return b"XYZ" + iv + ciphertext + encryptor.tag


class ServerRound:
    """Server side SRP state for one init/complete exchange."""

    def __init__(self, email: str, password: str, sp: str, salt: bytes,
                 iterations: int, a_public: bytes) -> None:
        digest = sha256(password.encode("utf-8"))
        material = digest if sp == "s2k" else digest.hex().encode("ascii")
        password_key = hashlib.pbkdf2_hmac("sha256", material, salt, iterations, 32)
        # ccsrp_generate_x with noUsernameInX: no username, ":" kept.
        identity_hash = sha256(b":", password_key)
        x = int.from_bytes(sha256(salt, identity_hash), "big")
        self.v = pow(SRP_G, x, SRP_N)
        k = int.from_bytes(sha256(pad(SRP_N), pad(SRP_G)), "big")
        self.b = int.from_bytes(secrets.token_bytes(32), "big")
        self.public = (k * self.v + pow(SRP_G, self.b, SRP_N)) % SRP_N
        self.a_public = int.from_bytes(a_public, "big")
        u = int.from_bytes(sha256(pad(self.a_public), pad(self.public)), "big")
        premaster = pow(self.a_public * pow(self.v, u, SRP_N) % SRP_N, self.b, SRP_N)
        self.session_key = sha256(pad(premaster))
        hashes_xor = bytes(
            left ^ right
            for left, right in zip(sha256(pad(SRP_N)), sha256(pad(SRP_G)))
        )
        self.m1 = sha256(
            hashes_xor,
            sha256(email.encode("utf-8")),
            salt,
            pad(self.a_public),
            pad(self.public),
            self.session_key,
        )
        self.m2 = sha256(pad(self.a_public), self.m1, self.session_key)


class MockGrandSlamServer:
    """Offline Grand Slam endpoint implementing the SRP login flow.

    The server side math mirrors corecrypto's ccsrp server: the client
    is only accepted when its M1 matches, so these tests exercise the
    real SRP math, not a replay of the client's own calculations.
    """

    def __init__(
        self,
        *,
        email: str = EMAIL,
        password: str = PASSWORD,
        adsid: str = ADSID,
        idms_token: str = IDMS_TOKEN,
        gs_token: str = GS_TOKEN,
        expiry_ms: int = EXPIRY_MS,
        first_name: str = "Test",
        last_name: str = "User",
        sp: str = "s2k_fo",
        needs_2fa: bool = False,
        correct_code: str = "123456",
        tamper_m2: bool = False,
        tamper_np: bool = False,
        bad_et: bytes | None = None,
        omit_init_key: str | None = None,
        init_error: tuple[int, str] | None = None,
        nested_validate: bool = False,
    ) -> None:
        self.email = email
        self.password = password
        self.adsid = adsid
        self.idms_token = idms_token
        self.gs_token = gs_token
        self.expiry_ms = expiry_ms
        self.first_name = first_name
        self.last_name = last_name
        self.sp = sp
        self.needs_2fa = needs_2fa
        self.correct_code = correct_code
        self.tamper_m2 = tamper_m2
        self.tamper_np = tamper_np
        self.bad_et = bad_et
        self.omit_init_key = omit_init_key
        self.init_error = init_error
        self.nested_validate = nested_validate

        self.salt = b"\x9a" * 16
        self.iterations = 5
        self.sk = secrets.token_bytes(32)
        self.spd_challenge = secrets.token_bytes(16)

        self.rounds: dict[str, ServerRound] = {}
        self.posts: list[dict[str, Any]] = []
        self.gets: list[tuple[str, dict[str, str]]] = []
        self.codes_seen: list[str | None] = []
        self.two_factor_satisfied = False

    # ------------------------------------------------------ client factory

    def make_client(self) -> GrandSlamClient:
        client = GrandSlamClient(FakeAnisetteProvider())
        client.http = FakeSession(self)  # type: ignore[assignment]
        return client

    def authenticate(
        self, password: str = PASSWORD, codes: list[str | None] | None = None
    ) -> tuple[GrandSlamClient, AppleSession]:
        queue = list(codes) if codes is not None else [self.correct_code]

        def provider() -> str | None:
            return queue.pop(0) if queue else None

        client = self.make_client()
        return client, client.authenticate(self.email, password, provider)

    # ------------------------------------------------------------- serving

    def handle_post(self, url: str, data: bytes, headers: dict[str, str]) -> requests.Response:
        assert url == GSA_ENDPOINT
        body = plistlib.loads(data)
        assert isinstance(body, dict), "request body is not a plist dictionary"
        self.posts.append(body)
        request: dict[str, Any] = body["Request"]
        assert isinstance(request, dict), "request body has no Request dictionary"
        operation = request["o"]
        if operation == "init":
            response = self._serve_init(request)
        elif operation == "complete":
            response = self._serve_complete(request)
        elif operation == "apptokens":
            response = self._serve_apptokens(request)
        else:
            response = {"Status": {"ec": -1, "em": f"unknown operation {operation}"}}
        # The real GSA endpoint wraps every operation response in a
        # top level "Response" dictionary.
        return _plist_response({"Response": response})

    def handle_get(self, url: str, headers: dict[str, str]) -> requests.Response:
        self.gets.append((url, headers))
        if url == GSA_TWO_FACTOR_TRIGGER_URL:
            return _response(b"", status=200)
        if url == GSA_TWO_FACTOR_VALIDATE_URL:
            code = headers.get("security-code")
            self.codes_seen.append(code)
            if code == self.correct_code:
                self.two_factor_satisfied = True
                status: dict[str, object] = {"ec": 0, "em": ""}
            else:
                status = {"ec": -21669, "em": "Incorrect security code"}
            if self.nested_validate:
                return _plist_response({"Status": status})
            return _plist_response(status)
        raise AssertionError(f"unexpected GET {url}")

    def _serve_init(self, request: dict[str, object]) -> dict[str, object]:
        if self.init_error is not None:
            code, message = self.init_error
            return {"Status": {"ec": code, "em": message}}
        if request["u"] != self.email:
            raise AssertionError("init request is for a different Apple ID")
        if request["ps"] != ["s2k", "s2k_fo"]:
            raise AssertionError("init request must offer both s2k flavors")
        a_public = request["A2k"]
        if not isinstance(a_public, bytes) or len(a_public) > SRP_SIZE:
            raise AssertionError("init request has no valid A2k")
        round_ = ServerRound(
            self.email, self.password, self.sp, self.salt, self.iterations, a_public
        )
        challenge = secrets.token_hex(8)
        self.rounds[challenge] = round_
        response: dict[str, object] = {
            "sp": self.sp,
            "c": challenge,
            "s": self.salt,
            "i": self.iterations,
            "B": pad(round_.public),
            "Status": {"ec": 0},
        }
        if self.omit_init_key is not None:
            response.pop(self.omit_init_key, None)
        return response

    def _serve_complete(self, request: dict[str, object]) -> dict[str, object]:
        challenge = request["c"]
        if not isinstance(challenge, str) or challenge not in self.rounds:
            return {"Status": {"ec": -22406, "em": "Unknown challenge"}}
        round_ = self.rounds[challenge]
        m1 = request["M1"]
        if not isinstance(m1, bytes) or m1 != round_.m1:
            return {"Status": {"ec": -22406, "em": "Incorrect user name or password"}}
        m2 = b"\x00" * 32 if self.tamper_m2 else round_.m2
        login_plist = {
            "adsid": self.adsid,
            "GsIdmsToken": self.idms_token,
            "sk": self.sk,
            "c": self.spd_challenge,
            "fn": self.first_name,
            "ln": self.last_name,
        }
        spd = cbc_encrypt(
            hmac.new(round_.session_key, b"extra data key:", hashlib.sha256).digest(),
            hmac.new(round_.session_key, b"extra data iv:", hashlib.sha256).digest()[:16],
            plistlib.dumps(login_plist, fmt=plistlib.FMT_XML),
        )
        sc = b"security-info"
        np_value = hmac.new(
            hmac.new(round_.session_key, b"HMAC key:", hashlib.sha256).digest(),
            negotiation_transcript(self.sp, spd, sc),
            hashlib.sha256,
        ).digest()
        if self.tamper_np:
            np_value = b"\x00" * 32
        status: dict[str, object] = {"ec": 0}
        if self.needs_2fa and not self.two_factor_satisfied:
            status["au"] = "trustedDeviceSecondaryAuth"
        return {"M2": m2, "spd": spd, "sc": sc, "np": np_value, "Status": status}

    def _serve_apptokens(self, request: dict[str, object]) -> dict[str, object]:
        if request["u"] != self.adsid:
            raise AssertionError("apptokens request must use the adsid as u")
        if request["app"] != [GSA_APP_NAME]:
            raise AssertionError("apptokens request must name the Xcode app")
        if request["t"] != self.idms_token:
            raise AssertionError("apptokens request must carry the GsIdmsToken")
        if request["c"] != self.spd_challenge:
            raise AssertionError("apptokens request must carry the spd challenge")
        expected_checksum = hmac.new(
            self.sk,
            b"apptokens" + self.adsid.encode("utf-8") + GSA_APP_NAME.encode("utf-8"),
            hashlib.sha256,
        ).digest()
        if request["checksum"] != expected_checksum:
            raise AssertionError("apptokens checksum does not match the sk HMAC")
        token_plist = {"t": {GSA_APP_NAME: {"token": self.gs_token, "expiry": self.expiry_ms}}}
        et = gcm_encrypt_xyz(self.sk, plistlib.dumps(token_plist, fmt=plistlib.FMT_XML))
        if self.bad_et is not None:
            et = self.bad_et
        return {"et": et, "Status": {"ec": 0}}


class FakeSession:
    """The only HTTP seam the GrandSlamClient uses."""

    def __init__(self, server: MockGrandSlamServer) -> None:
        self.server = server

    def post(self, url: str, data: bytes | None = None, headers: dict[str, str] | None = None,
             timeout: float | None = None,
             allow_redirects: bool = True) -> requests.Response:
        assert data is not None
        return self.server.handle_post(url, data, headers or {})

    def get(self, url: str, headers: dict[str, str] | None = None,
            timeout: float | None = None,
            allow_redirects: bool = True) -> requests.Response:
        return self.server.handle_get(url, headers or {})


def _response(body: bytes, status: int = 200) -> requests.Response:
    response = requests.Response()
    response.status_code = status
    response._content = body
    response.headers["Content-Type"] = "text/x-xml-plist"
    return response


def _plist_response(dictionary: dict[str, object], status: int = 200) -> requests.Response:
    return _response(plistlib.dumps(dictionary, fmt=plistlib.FMT_XML), status)


# --------------------------------------------------------------- anisette


def test_anisette_missing_framework_raises_clear_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(anisette_module, "AOSKIT_PATH", str(tmp_path / "AOSKit.framework"))
    monkeypatch.setattr(anisette_module, "AUTHKIT_PATH", str(tmp_path / "AuthKit.framework"))
    provider = AnisetteProvider()
    with pytest.raises(AnisetteError) as excinfo:
        provider.get_anisette()
    assert "AOSKit.framework" in str(excinfo.value)


def test_client_info_drops_the_application_group() -> None:
    class Device:
        def serverFriendlyDescription(self) -> str:
            return "<Mac15,12> <macOS;26.6.2;25G83> <com.apple.AuthKit/1 ((null)/1.0)>"

    description = AnisetteProvider()._device_description(Device())
    assert description == "<Mac15,12> <macOS;26.6.2;25G83>"


def test_client_info_falls_back_to_the_xcode_template() -> None:
    description = AnisetteProvider()._device_description(object())
    assert description == CLIENT_INFO_TEMPLATE.format(
        device_model=anisette_module.FALLBACK_DEVICE_MODEL,
        os_name="macOS",
        os_version=anisette_module.FALLBACK_OS_VERSION,
        build=anisette_module.FALLBACK_OS_BUILD,
    )


def test_build_cpd_matches_the_altsign_dictionary() -> None:
    provider = FakeAnisetteProvider()
    cpd = build_cpd(provider, "2026-01-27T10:11:12Z")
    assert cpd == {
        "bootstrap": True,
        "icscrec": True,
        "loc": "en_US",
        "pbe": False,
        "prkgen": True,
        "svct": "iCloud",
        "X-Apple-I-Client-Time": "2026-01-27T10:11:12Z",
        "X-Apple-Locale": "en_US",
        "X-Apple-I-TimeZone": "GMT+7",
        "X-Apple-I-MD": "otp-1",
        "X-Apple-I-MD-LU": "local-user-value",
        "X-Apple-I-MD-M": "machine-id-value",
        "X-Apple-I-MD-RINFO": 84215040,
        "X-Mme-Device-Id": "device-udid-value",
        "X-Apple-I-SRL-NO": FALLBACK_DEVICE_SERIAL,
    }


# ------------------------------------------------------------ login: plist


def test_full_login_parses_every_plist_and_returns_the_session() -> None:
    server = MockGrandSlamServer()
    _, session = server.authenticate()

    assert isinstance(session, AppleSession)
    assert session.dsid == ADSID
    assert session.gs_token == GS_TOKEN
    expected_expiry = datetime.fromtimestamp(EXPIRY_MS / 1000, tz=UTC)
    assert session.token_expiry == expected_expiry
    assert session.account == Account(
        first_name="Test",
        last_name="User",
        email=EMAIL,
        dsid=ADSID,
    )

    # Request shapes: Header wrapper, operation order, fresh anisette per
    # request (the OTP is single use).
    assert [body["Request"]["o"] for body in server.posts] == ["init", "complete", "apptokens"]
    for body in server.posts:
        assert body["Header"] == {"Version": GSA_PROTOCOL_VERSION}
    init_request = server.posts[0]["Request"]
    assert init_request["u"] == EMAIL
    assert init_request["ps"] == ["s2k", "s2k_fo"]
    assert isinstance(init_request["A2k"], bytes)
    assert len(init_request["A2k"]) == SRP_SIZE
    assert init_request["cpd"]["X-Apple-I-MD"] == "otp-1"
    assert server.posts[1]["Request"]["cpd"]["X-Apple-I-MD"] == "otp-2"
    assert server.posts[2]["Request"]["cpd"]["X-Apple-I-MD"] == "otp-3"

    # The apptokens request carries the spd values, not the init challenge.
    app_request = server.posts[2]["Request"]
    assert app_request["u"] == ADSID
    assert app_request["app"] == [GSA_APP_NAME]
    assert app_request["t"] == IDMS_TOKEN
    assert app_request["c"] == server.spd_challenge


def test_login_with_s2k_password_flavor() -> None:
    server = MockGrandSlamServer(sp="s2k")
    _, session = server.authenticate()
    assert session.dsid == ADSID


def test_login_error_code_surfaces_the_apple_message() -> None:
    server = MockGrandSlamServer(init_error=(-1, "Something broke"))
    with pytest.raises(AuthError) as excinfo:
        server.authenticate()
    assert "-1" in str(excinfo.value)
    assert "Something broke" in str(excinfo.value)


def test_missing_init_field_is_an_auth_error() -> None:
    server = MockGrandSlamServer(omit_init_key="B")
    with pytest.raises(AuthError) as excinfo:
        server.authenticate()
    assert "'B'" in str(excinfo.value)


def test_mismatched_server_proof_fails_the_handshake() -> None:
    server = MockGrandSlamServer(tamper_m2=True)
    with pytest.raises(AuthError) as excinfo:
        server.authenticate()
    assert "server proof" in str(excinfo.value)


def test_mismatched_negotiation_hash_fails_the_handshake() -> None:
    server = MockGrandSlamServer(tamper_np=True)
    with pytest.raises(AuthError) as excinfo:
        server.authenticate()
    assert "negotiation hash" in str(excinfo.value)


def test_truncated_or_bad_magic_app_token_is_an_auth_error() -> None:
    server = MockGrandSlamServer(bad_et=b"ABC" + b"\x00" * 40)
    with pytest.raises(AuthError) as excinfo:
        server.authenticate()
    assert "app token" in str(excinfo.value)

    server = MockGrandSlamServer(bad_et=b"XYZ" + b"\x00" * 10)
    with pytest.raises(AuthError):
        server.authenticate()


# ------------------------------------------------------- login: error map


def test_wrong_password_maps_to_auth_error() -> None:
    server = MockGrandSlamServer()
    with pytest.raises(AuthError) as excinfo:
        server.authenticate(password="not the password")
    assert isinstance(excinfo.value, AuthError)
    assert not isinstance(excinfo.value, TwoFactorError)
    assert "Apple ID or password" in str(excinfo.value)


def test_incorrect_credentials_error_code_maps_to_auth_error() -> None:
    server = MockGrandSlamServer(init_error=(-22406, "Incorrect user name or password"))
    with pytest.raises(AuthError) as excinfo:
        server.authenticate()
    assert not isinstance(excinfo.value, TwoFactorError)


# ------------------------------------------------------------------- 2FA


def test_two_factor_success_repeats_the_srp_exchange() -> None:
    server = MockGrandSlamServer(needs_2fa=True, correct_code="246810")
    _, session = server.authenticate(codes=["000000", "246810"])

    assert session.dsid == ADSID
    assert session.gs_token == GS_TOKEN
    # The SRP exchange repeats after the code is accepted: two init calls.
    operations = [body["Request"]["o"] for body in server.posts]
    assert operations == ["init", "complete", "init", "complete", "apptokens"]

    trigger_urls = [url for url, _ in server.gets if url == GSA_TWO_FACTOR_TRIGGER_URL]
    validate_entries = [
        (url, headers)
        for url, headers in server.gets
        if url == GSA_TWO_FACTOR_VALIDATE_URL
    ]
    assert len(trigger_urls) == 1
    assert len(validate_entries) == 2
    assert server.codes_seen == ["000000", "246810"]

    # The 2FA header contract from AltSign requestTwoFactorCodeForDSID.
    _, validate_headers = validate_entries[0]
    identity = base64.b64encode(f"{ADSID}:{IDMS_TOKEN}".encode()).decode("ascii")
    assert validate_headers["User-Agent"] == XCODE_USER_AGENT
    assert validate_headers["X-Apple-Identity-Token"] == identity
    assert validate_headers["security-code"] == "000000"
    # AltServer spells this header "X-Mme-Device-Id" (lowercase "me").
    assert validate_headers["X-Mme-Device-Id"] == "device-udid-value"
    assert validate_headers["X-Apple-I-MD-M"] == "machine-id-value"


def test_two_factor_wrong_code_retries_then_raises_after_limit() -> None:
    server = MockGrandSlamServer(needs_2fa=True, correct_code="246810")
    calls: list[str | None] = []

    def always_wrong() -> str | None:
        calls.append("111111")
        return "111111"

    client = server.make_client()
    with pytest.raises(TwoFactorError) as excinfo:
        client.authenticate(EMAIL, PASSWORD, always_wrong)

    assert len(calls) == MAX_TWO_FACTOR_ATTEMPTS
    assert len(server.codes_seen) == MAX_TWO_FACTOR_ATTEMPTS
    assert server.two_factor_satisfied is False
    assert f"{MAX_TWO_FACTOR_ATTEMPTS} times" in str(excinfo.value)


def test_two_factor_aborts_when_the_provider_returns_none() -> None:
    server = MockGrandSlamServer(needs_2fa=True)
    client = server.make_client()
    with pytest.raises(TwoFactorError):
        client.authenticate(EMAIL, PASSWORD, lambda: None)
    assert server.codes_seen == []


def test_two_factor_accepts_nested_status_plist() -> None:
    server = MockGrandSlamServer(needs_2fa=True, nested_validate=True)
    _, session = server.authenticate(codes=["123456"])
    assert session.gs_token == GS_TOKEN


def test_unsupported_second_factor_step_is_an_auth_error() -> None:
    server = MockGrandSlamServer(needs_2fa=True, correct_code="123456")
    # Simulate Apple asking for SMS based 2FA instead.
    original = server._serve_complete

    def serve_complete(request: dict[str, object]) -> dict[str, object]:
        response = original(request)
        if isinstance(response["Status"], dict):
            response["Status"] = {**response["Status"], "au": "secondaryAuth"}
        return response

    server._serve_complete = serve_complete  # type: ignore[method-assign]
    with pytest.raises(AuthError) as excinfo:
        server.authenticate()
    assert "secondaryAuth" in str(excinfo.value)


# ----------------------------------------------------------- http details


def test_non_200_response_is_an_auth_error() -> None:
    server = MockGrandSlamServer()

    class FailingSession(FakeSession):
        def post(  # type: ignore[no-untyped-def]
            self, url, data=None, headers=None, timeout=None, allow_redirects=True
        ):
            return _response(b"gateway timeout", status=502)

    client = GrandSlamClient(FakeAnisetteProvider())
    client.http = FailingSession(server)  # type: ignore[assignment]
    with pytest.raises(AuthError) as excinfo:
        client.authenticate(EMAIL, PASSWORD, lambda: "123456")
    assert "502" in str(excinfo.value)


def test_rate_limit_is_reported_with_a_wait_hint() -> None:
    server = MockGrandSlamServer()

    class RateLimitedSession(FakeSession):
        def post(  # type: ignore[no-untyped-def]
            self, url, data=None, headers=None, timeout=None, allow_redirects=True
        ):
            return _response(b"too many requests", status=429)

    client = GrandSlamClient(FakeAnisetteProvider())
    client.http = RateLimitedSession(server)  # type: ignore[assignment]
    with pytest.raises(AuthError) as excinfo:
        client.authenticate(EMAIL, PASSWORD, lambda: "123456")
    assert "rate limiting" in str(excinfo.value)
    assert "wait 30 to 60 minutes" in (excinfo.value.hint or "")


def test_unparseable_response_is_an_auth_error() -> None:
    server = MockGrandSlamServer()

    class GarbageSession(FakeSession):
        def post(  # type: ignore[no-untyped-def]
            self, url, data=None, headers=None, timeout=None, allow_redirects=True
        ):
            return _response(b"this is not a plist at all")

    client = GrandSlamClient(FakeAnisetteProvider())
    client.http = GarbageSession(server)  # type: ignore[assignment]
    with pytest.raises(AuthError):
        client.authenticate(EMAIL, PASSWORD, lambda: "123456")


# ------------------------------------------------------------- keychain


class FakeSecurityRunner:
    """In-memory stand-in for the macOS security CLI.

    Implements exactly the commands KeychainStore issues, including the
    "security" convention of printing the secret plus one trailing
    newline and exiting 44 when the item is missing.
    """

    def __init__(self) -> None:
        self.items: dict[tuple[str, str], str] = {}
        self.identities: set[str] = set()
        self.imports: list[str] = []
        self.fail_command: str | None = None

    def __call__(self, args: list[str]) -> subprocess.CompletedProcess[bytes]:
        command = args[0]
        if command == self.fail_command:
            return subprocess.CompletedProcess(
                args, returncode=36, stdout=b"", stderr=b"security: some denied."
            )
        if command == "add-generic-password":
            account = _option(args, "-a")
            service = _option(args, "-s")
            secret = _option(args, "-w")
            assert account and service and secret is not None
            self.items[(account, service)] = secret
            return subprocess.CompletedProcess(args, returncode=0, stdout=b"", stderr=b"")
        if command == "find-generic-password":
            key = (_option(args, "-a"), _option(args, "-s"))
            if key not in self.items:
                return self._not_found(args)
            secret = self.items[key]
            return subprocess.CompletedProcess(
                args, returncode=0, stdout=secret.encode("utf-8") + b"\n", stderr=b""
            )
        if command == "delete-generic-password":
            key = (_option(args, "-a"), _option(args, "-s"))
            if key not in self.items:
                return self._not_found(args)
            del self.items[key]
            return subprocess.CompletedProcess(args, returncode=0, stdout=b"", stderr=b"")
        if command == "find-identity":
            lines = [
                f'  {index + 1}) {"A1B2C3D4" * 5} "{name}"'
                for index, name in enumerate(sorted(self.identities))
            ]
            output = ("\n".join(lines) + "\n").encode("utf-8") if lines else b""
            return subprocess.CompletedProcess(args, returncode=0, stdout=output, stderr=b"")
        if command == "import":
            self.imports.append(args[1])
            self.identities.add("Apple Development: user@example.com (AB12CD34EF)")
            return subprocess.CompletedProcess(args, returncode=0, stdout=b"", stderr=b"")
        if command == "delete-certificate":
            name = _option(args, "-c")
            self.identities = {item for item in self.identities if item != name}
            return subprocess.CompletedProcess(args, returncode=0, stdout=b"", stderr=b"")
        raise AssertionError(f"unexpected security command: {args}")

    def run_stdin(self, line: str) -> subprocess.CompletedProcess[bytes]:
        """Emulate "security -i" by splitting the quoted command line."""
        return self(shlex.split(line))

    @staticmethod
    def _not_found(args: list[str]) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(
            args, returncode=44, stdout=b"", stderr=b"security: SecKeychainSearchCopyNext: absent."
        )


def make_store(runner: FakeSecurityRunner) -> KeychainStore:
    """KeychainStore wired to the in-memory runner for argv and stdin."""
    return KeychainStore(runner=runner, stdin_runner=runner.run_stdin)


def _option(args: list[str], flag: str) -> str:
    index = args.index(flag)
    return args[index + 1]


def make_session() -> AppleSession:
    account = Account(
        first_name="Test",
        last_name="User",
        email=EMAIL,
        dsid=ADSID,
    )
    return AppleSession(
        dsid=ADSID,
        gs_token=GS_TOKEN,
        token_expiry=datetime(2026, 6, 1, 12, 30, tzinfo=UTC) + timedelta(hours=2),
        account=account,
    )


def test_keychain_session_round_trip_against_mock() -> None:
    runner = FakeSecurityRunner()
    store = make_store(runner)
    session = make_session()

    store.save_session(EMAIL, session)
    assert (EMAIL, SERVICE_SESSION) in runner.items

    loaded = store.load_session(EMAIL)
    assert loaded is not None
    assert loaded == session
    assert loaded.account == session.account
    assert loaded.token_expiry.tzinfo is not None


def test_keychain_expiry_survives_a_restart() -> None:
    runner = FakeSecurityRunner()
    make_store(runner).save_session(EMAIL, make_session())

    # A brand new store over the same keychain, like a new process.
    restarted = make_store(runner)
    loaded = restarted.load_session(EMAIL)
    assert loaded is not None
    assert loaded.token_expiry == make_session().token_expiry


def test_keychain_load_missing_returns_none_and_delete_is_idempotent() -> None:
    runner = FakeSecurityRunner()
    store = make_store(runner)
    assert store.load_session(EMAIL) is None
    assert store.delete_session(EMAIL) is False

    store.save_session(EMAIL, make_session())
    assert store.delete_session(EMAIL) is True
    assert store.load_session(EMAIL) is None
    assert store.delete_session(EMAIL) is False


def test_keychain_corrupt_blob_raises_keychain_error() -> None:
    runner = FakeSecurityRunner()
    runner.items[(EMAIL, SERVICE_SESSION)] = "not json at all"
    store = make_store(runner)
    with pytest.raises(KeychainError) as excinfo:
        store.load_session(EMAIL)
    assert "corrupt" in str(excinfo.value)


def test_keychain_blob_missing_expiry_raises_keychain_error() -> None:
    runner = FakeSecurityRunner()
    runner.items[(EMAIL, SERVICE_SESSION)] = json.dumps({"dsid": ADSID, "gs_token": GS_TOKEN})
    store = make_store(runner)
    with pytest.raises(KeychainError):
        store.load_session(EMAIL)


def test_keychain_security_failure_raises_keychain_error() -> None:
    runner = FakeSecurityRunner()
    runner.fail_command = "add-generic-password"
    store = make_store(runner)
    with pytest.raises(KeychainError) as excinfo:
        store.save_session(EMAIL, make_session())
    assert "some denied" in str(excinfo.value)


def test_keychain_session_blob_never_stores_the_password() -> None:
    runner = FakeSecurityRunner()
    make_store(runner).save_session(EMAIL, make_session())
    stored = runner.items[(EMAIL, SERVICE_SESSION)]
    assert stored.startswith("b64:")
    blob = json.loads(base64.b64decode(stored[4:]))
    assert set(blob) == {"dsid", "gs_token", "token_expiry", "account"}
    assert "password" not in json.dumps(blob).lower()


def test_keychain_find_identity_matches_team_suffix() -> None:
    runner = FakeSecurityRunner()
    runner.identities = {
        "Apple Development: user@example.com (AB12CD34EF)",
        "iPhone Distribution: Example Inc (ZZ99YY77XX)",
    }
    store = make_store(runner)
    identity = store.find_identity("AB12CD34EF")
    assert identity is not None
    assert identity.team_identifier == "AB12CD34EF"
    assert identity.keychain_identity == "Apple Development: user@example.com (AB12CD34EF)"
    assert identity.certificate_pem is None
    assert store.find_identity("NOPE12345") is None


def test_keychain_import_identity_returns_the_new_identity() -> None:
    runner = FakeSecurityRunner()
    store = make_store(runner)
    name = store.import_identity("/tmp/cert.p12", "p12-pass", "AB12CD34EF")
    assert name == "Apple Development: user@example.com (AB12CD34EF)"
    assert store.find_identity("AB12CD34EF") is not None

    store.delete_identity(name)
    assert store.find_identity("AB12CD34EF") is None
    # Best effort: deleting again is not an error.
    store.delete_identity(name)


def test_keychain_reimport_into_existing_identity_disambiguates() -> None:
    runner = FakeSecurityRunner()
    runner.identities = {"Apple Development: user@example.com (AB12CD34EF)"}
    store = make_store(runner)
    name = store.import_identity("/tmp/cert.p12", "p12-pass", "(AB12CD34EF)")
    assert name == "Apple Development: user@example.com (AB12CD34EF)"


# ------------------------------------------------------------- taxonomy


def test_error_hierarchy_matches_the_taxonomy() -> None:
    assert issubclass(TwoFactorError, AuthError)
    assert issubclass(AuthError, SideloadError)
    assert issubclass(KeychainError, SideloadError)
    assert issubclass(AnisetteError, AuthError)
    two_factor = TwoFactorError("nope")
    assert two_factor.exit_code == 1
    assert isinstance(two_factor.hint, str) or two_factor.hint is None


def test_session_token_never_reaches_argv(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_run(argv, **kwargs):  # type: ignore[no-untyped-def]
        captured["argv"] = list(argv)
        captured["input"] = kwargs.get("input") or b""
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr("sideload.keychain.subprocess.run", fake_run)
    KeychainStore().save_session(EMAIL, make_session())

    argv = captured["argv"]
    assert isinstance(argv, list)
    assert argv == ["/usr/bin/security", "-i"]
    assert GS_TOKEN not in " ".join(str(part) for part in argv)
    line = captured["input"].decode("utf-8")
    parts = shlex.split(line)
    stored = parts[parts.index("-w") + 1]
    assert stored.startswith("b64:")
    assert GS_TOKEN.encode() in base64.b64decode(stored[4:])


def test_keychain_session_blob_survives_quotes_and_apostrophes() -> None:
    from dataclasses import replace

    runner = FakeSecurityRunner()
    store = make_store(runner)
    original = make_session()
    hostile = replace(
        original,
        gs_token="tok\"'\\+/=",
        account=replace(original.account, email="o'brien@example.com"),
    )
    store.save_session(EMAIL, hostile)
    stored = runner.items[(EMAIL, SERVICE_SESSION)]
    assert stored.startswith("b64:")
    assert "'" not in stored and '"' not in stored and "\\" not in stored
    assert store.load_session(EMAIL) == hostile


def test_keychain_apostrophe_account_round_trips() -> None:
    runner = FakeSecurityRunner()
    store = make_store(runner)
    email = "o'brien@example.com"
    store.save_session(email, make_session())
    assert store.load_session(email) == make_session()


def test_invalid_mid_error_has_provisioning_hint() -> None:
    with pytest.raises(AuthError) as excinfo:
        auth_module._raise_for_status(
            {"Status": {"ec": -80009, "em": "MID is invalid."}}, "init"
        )
    assert "anisette" in str(excinfo.value).lower()
    assert "System Settings" in (excinfo.value.hint or "")


def test_security_code_204_counts_as_success() -> None:
    class NoContentSession:
        def get(  # type: ignore[no-untyped-def]
            self, url, headers=None, timeout=None, allow_redirects=True
        ):
            return _response(b"", status=204)

    client = GrandSlamClient(FakeAnisetteProvider())
    client.http = NoContentSession()  # type: ignore[assignment]
    assert client._validate_security_code("adsid", "token", "123456") is True


def test_find_identity_ignores_developer_id_certificates() -> None:
    runner = FakeSecurityRunner()
    runner.identities = {
        "Developer ID Application: Example Developer (AB12CD34EF)",
        "Apple Development: user@example.com (AB12CD34EF)",
    }
    store = make_store(runner)
    identity = store.find_identity("AB12CD34EF")
    assert identity is not None
    assert identity.keychain_identity is not None
    assert identity.keychain_identity.startswith("Apple Development:")


def test_import_identity_resolves_same_common_name_with_team_note() -> None:
    runner = FakeSecurityRunner()
    runner.identities = {"Apple Development: user@example.com (AB12CD34EF)"}
    store = make_store(runner)
    name = store.import_identity("/tmp/does-not-matter.p12", "pass", "AB12CD34EF")
    assert name == "Apple Development: user@example.com (AB12CD34EF)"


def test_gsa_headers_disable_connection_reuse() -> None:
    client = GrandSlamClient(FakeAnisetteProvider())
    data = client.anisette.get_anisette()
    assert client._gsa_headers(data)["Connection"] == "close"
    assert client._two_factor_headers("adsid", "token")["Connection"] == "close"


def test_hsc_409_marks_two_factor_already_pushed() -> None:
    assert auth_module._two_factor_requirement({"hsc": 409}) == (True, True)
    assert auth_module._two_factor_requirement({"au": "trustedDeviceSecondaryAuth"}) == (True, False)
    assert auth_module._two_factor_requirement({}) == (False, False)


def test_locale_keyword_suffix_is_stripped() -> None:
    class Locale:
        def localeIdentifier(self) -> str:
            return "en_US@rg=skzzzz"

    class Device:
        def locale(self) -> Locale:
            return Locale()

    assert AnisetteProvider()._locale(Device()) == "en_US"


def test_security_code_rate_limit_has_wait_hint() -> None:
    class LimitedSession:
        def get(  # type: ignore[no-untyped-def]
            self, url, headers=None, timeout=None, allow_redirects=True
        ):
            return _response(b"", status=429)

    client = GrandSlamClient(FakeAnisetteProvider())
    client.http = LimitedSession()  # type: ignore[assignment]
    with pytest.raises(AuthError) as excinfo:
        client._validate_security_code("adsid", "token", "123456")
    assert "wait 30 to 60 minutes" in (excinfo.value.hint or "")


def test_parse_plist_accepts_openstep_ascii() -> None:
    parsed = auth_module._parse_plist(
        b'{ adsid = "X"; GsIdmsToken = "Y"; sk = <00ff>; }',
        "login response",
    )
    assert parsed["adsid"] == "X"
    assert parsed["GsIdmsToken"] == "Y"
    assert parsed["sk"] == b"\x00\xff"


def _openstep_plist(value: object) -> bytes:
    if isinstance(value, dict):
        items = []
        for key, item in value.items():
            safe_key = str(key) if str(key).replace("_", "").isalnum() else f'"{key}"'
            items.append(f"{safe_key} = {_openstep_plist(item).decode('utf-8')};")
        return ("{ " + " ".join(items) + " }").encode()
    if isinstance(value, bytes):
        return f"<{value.hex()}>".encode("ascii")
    if isinstance(value, str):
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'.encode()
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value).encode("ascii")
    raise TypeError(f"unsupported OpenStep value: {type(value).__name__}")


def test_full_login_accepts_openstep_ascii_spd(monkeypatch) -> None:
    original_dumps = plistlib.dumps

    def dumps(value, *args, **kwargs):  # type: ignore[no-untyped-def]
        if isinstance(value, dict) and "GsIdmsToken" in value:
            return _openstep_plist(value)
        return original_dumps(value, *args, **kwargs)

    monkeypatch.setattr(plistlib, "dumps", dumps)
    server = MockGrandSlamServer()
    _, session = server.authenticate()
    assert session.dsid == ADSID
    assert session.gs_token == GS_TOKEN
