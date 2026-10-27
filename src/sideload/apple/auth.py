"""Apple ID authentication via the Grand Slam (GSA) SRP-6a protocol.

Verified against AltSign (AltSign/Apple API/ALTAppleAPI+Authentication.m,
heavily based on kabiroberai's sample code), SideStore's current Rust
implementation (SideStore/apple-private-apis, icloud-auth/src/client.rs),
and Apple's own corecrypto ccsrp sources (ccsrp_client.c, ccsrp_priv.h).
All three ship this exact flow in production today; it is the only path
that yields a Grand Slam token usable against developerservices2.

Protocol outline (exact shapes; the AUTH agent implements precisely this):

1. init
   POST https://gsa.apple.com/grandslam/GsService2
   Headers: Content-Type: text/x-xml-plist, Accept: */*,
            X-MMe-Client-Info: <anisette device description>,
            User-Agent: "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0"
   Body (XML plist): {"Header": {"Version": "1.0.1"}, "Request": {
       "o": "init",
       "u": <apple id email>,
       "ps": ["s2k", "s2k_fo"],
       "A2k": <bytes, client SRP ephemeral A>,
       "cpd": <client parameter dict, see build_cpd>}}
   Response: {"sp": "s2k"|"s2k_fo", "c": <bytes challenge>,
             "s": <bytes salt>, "i": <iterations>, "B": <bytes>,
             "Status": {"ec": 0}}
   SRP group: RFC 5054 2048 bit, SHA-256, with the "no username in x"
   option set (ccsrp_client_set_noUsernameInX(true) in AltSign): the
   username is dropped from the inner hash but the ":" separator stays,
   so x = SHA256(salt + SHA256(":" + password_key)) exactly as in
   corecrypto's ccsrp_generate_x.
   Password key: PBKDF2-HMAC-SHA256(SHA256(password digest), salt, i, 32
   bytes) where the digest is hex encoded SHA256(password) for "s2k_fo"
   and raw SHA256(password) for "s2k" (AltSign ALTPBKDF2SRP).
   Session key K = SHA256(PAD(S)) with S padded to the group size, and
   M1/M2/k/u use the padded forms as ccsrp does (the default
   CCSRP_OPTION_SRP6a_HASH variant never skips leading zeros).

2. complete
   Same endpoint, Request: {"o": "complete", "u": <email>, "c": <c from
   init>, "M1": <bytes client proof>, "cpd": <cpd>}
   Response: {"M2": <bytes server proof>, "spd": <bytes encrypted login
   data>, "sc": <bytes>, "np": <bytes>, "Status": {...}}
   Verify M2, then verify np against a running SHA-256 transcript of
   "s2k,s2k_fo||<sp>|<len32 spd>|<len32 sc>|" keyed with
   HMAC-SHA256(K, "HMAC key:") (AltSign ALTDigestUpdate* helpers), then
   decrypt spd with AES-256-CBC using keys
   HMAC-SHA256(K, "extra data key:") and
   HMAC-SHA256(K, "extra data iv:"); PKCS7 padding. The decrypted XML
   plist contains "adsid" (the DSID), "GsIdmsToken", "sk" (session key),
   "c", and the account names "fn" and "ln".
   Status error codes: -22406 means incorrect credentials.

3. two factor (when Status contains "au": "trustedDeviceSecondaryAuth")
   a. Trigger the code push:
      GET https://gsa.apple.com/auth/verify/trusteddevice
      Headers: X-Apple-Identity-Token: base64("<adsid>:<GsIdmsToken>")
               plus the Xcode/anisette headers from send_request.
   b. Validate:
      GET https://gsa.apple.com/grandslam/GsService2/validate
      Headers: same as (a) plus "security-code": <six digit code>.
      Error -21669 means wrong code. On success the whole SRP exchange
      is repeated from step 1; the account is now trusted and the flow
      proceeds to apptokens.

4. apptokens
   Same endpoint, Request: {"o": "apptokens", "u": <adsid>,
       "app": ["com.apple.gs.xcode.auth"], "c": <c from spd>,
       "t": <GsIdmsToken>, "cpd": <cpd>,
       "checksum": HMAC-SHA256(sk, "apptokens" + adsid + app)}
   The checksum uses the decrypted spd's "sk" directly as the HMAC key,
   exactly as AltSign (ALTCreateAppTokensChecksum) and SideStore
   (create_checksum) do. Note: DESIGN.md section 4.2 describes a nested
   HMAC-SHA256(HMAC-SHA256(session_key, "HMAC key:"), ...) here; that
   derivation belongs to the np check in step 2, and both production
   references agree the apptokens checksum is the plain HMAC over sk.
   Response: {"et": <bytes>, ...}
   Decrypt et with AES-GCM under the "sk" key: format is "XYZ" magic,
   16 byte IV, ciphertext, 16 byte tag, and the magic bytes are GCM
   authenticated data. The decrypted XML plist holds
   {"t": {"com.apple.gs.xcode.auth": {"token": <gs token>,
   "expiry": <epoch ms>}}}.

The password is used in memory only for the PBKDF2 step and is then
dropped; it is never persisted.

Ownership: AUTH agent.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import plistlib
import secrets
import struct
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

import requests
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from sideload.apple.anisette import AnisetteProvider
from sideload.errors import AuthError, TwoFactorError
from sideload.models import Account, AnisetteData, AppleSession

GSA_ENDPOINT = "https://gsa.apple.com/grandslam/GsService2"
GSA_TWO_FACTOR_TRIGGER_URL = "https://gsa.apple.com/auth/verify/trusteddevice"
GSA_TWO_FACTOR_VALIDATE_URL = "https://gsa.apple.com/grandslam/GsService2/validate"
GSA_PROTOCOL_VERSION = "1.0.1"
GSA_APP_NAME = "com.apple.gs.xcode.auth"

# Error codes from the GSA Status dictionary.
GSA_ERR_INCORRECT_CREDENTIALS = -22406
GSA_ERR_INCORRECT_SECURITY_CODE = -21669

# User agent AltSign sends for Grand Slam requests.
GSA_USER_AGENT = "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0"

# Values AltSign uses for the Xcode side headers on developer requests.
XCODE_USER_AGENT = "Xcode"
XCODE_VERSION = "11.2 (11B41)"
XCODE_APP_INFO = "com.apple.gs.xcode.auth"

# A wrong 2FA code is asked again up to this many times (ACCEPTANCE.md).
MAX_TWO_FACTOR_ATTEMPTS = 3

# Network timeout for all Grand Slam requests, in seconds.
GSA_TIMEOUT = 30.0

# The 2FA request headers are built with a fresh OTP per call, the same
# way AltSign's requestTwoFactorCodeForDSID sends them.
_XCODE_IDENTITY_TOKEN_PREFIX = "X-Apple-Identity-Token"

# RFC 5054 appendix A, 2048 bit group: the exact prime ccsrp's
# ccsrp_gp_rfc5054_2048 uses (g = 2).
_SRP_GROUP_HEX = (
    "ac6bdb41324a9a9bf166de5e1389582faf72b6651987ee07fc3192943db56050"
    "a37329cbb4a099ed8193e0757767a13dd52312ab4b03310dcd7f48a9da04fd50"
    "e8083969edb767b0cf6095179a163ab3661a05fbd5faaae82918a9962f0b93b8"
    "55f97993ec975eeaa80d740adbf4ff747359d041d5c33ea71d281e446b14773b"
    "ca97b43a23fb801676bd207a436c6481f1d2b9078717461a5b9d32e688f87748"
    "544523b524b0d57d5ea77a2775d2ecfa032cfbdbf52fb3786160279004e57ae6"
    "af874e7303ce53299ccc041c7bc308d82a5698f3a8d0c38271ae35f8e9dbfbb6"
    "94b5c803d89f7ae435de236d525f54759b65e372fcd68ef20fa7111f9e4aff73"
)

_SRP_N: Final[int] = int(_SRP_GROUP_HEX, 16)
_SRP_G: Final[int] = 2
# Byte size of one SRP group element (2048 bit).
_SRP_KEY_BYTES: Final[int] = 256
# Byte size of the SRP private ephemeral (256 bit minimum, SRP-6a).
_SRP_PRIVATE_BYTES: Final[int] = 32


# ------------------------------------------------------------- SRP-6a


def _sha256(*chunks: bytes) -> bytes:
    digest = hashlib.sha256()
    for chunk in chunks:
        digest.update(chunk)
    return digest.digest()


def _int_from_bytes(data: bytes) -> int:
    return int.from_bytes(data, "big")


def _pad_int(value: int) -> bytes:
    """Big-endian bytes padded to the group size, as ccsrp exports."""
    return value.to_bytes(_SRP_KEY_BYTES, "big")


@dataclass(frozen=True)
class _SrpExchange:
    """Client side results of one SRP challenge (init plus complete)."""

    a_public: bytes
    m1: bytes
    m2: bytes
    session_key: bytes


def _srp_public_ephemeral(a: bytes) -> bytes:
    return _pad_int(pow(_SRP_G, _int_from_bytes(a), _SRP_N))


def _srp_password_key(password: str, salt: bytes, iterations: int, sp: str) -> bytes:
    """ALTPBKDF2SRP: PBKDF2-HMAC-SHA256 over the SHA-256 password digest.

    "s2k" feeds the raw 32 byte digest; "s2k_fo" feeds its 64 byte
    lowercase hex encoding.
    """
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    material = digest if sp == "s2k" else digest.hex().encode("ascii")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(material)


def _srp_client_challenge(
    username: str,
    password_key: bytes,
    salt: bytes,
    a: bytes,
    b_bytes: bytes,
) -> _SrpExchange:
    """Compute K, M1, and the expected M2 for Apple's SRP variant.

    Mirrors ccsrp_client_process_challenge with SHA-256, the RFC 5054
    2048 bit group, and noUsernameInX enabled (see module docstring).
    """
    a_int = _int_from_bytes(a)
    a_public = _pad_int(pow(_SRP_G, a_int, _SRP_N))
    b_int = _int_from_bytes(b_bytes)
    if b_int % _SRP_N == 0:
        raise AuthError("The Grand Slam server returned an invalid SRP challenge (B).")
    b_padded = _pad_int(b_int)
    u = _int_from_bytes(_sha256(a_public, b_padded))
    if u == 0:
        raise AuthError("The Grand Slam server returned an invalid SRP challenge (u).")
    k = _int_from_bytes(_sha256(_pad_int(_SRP_N), _pad_int(_SRP_G)))
    # ccsrp_generate_x with noUsernameInX: drop the user, keep the ":".
    identity_hash = _sha256(b":", password_key)
    x = _int_from_bytes(_sha256(salt, identity_hash))
    base = (b_int - k * pow(_SRP_G, x, _SRP_N)) % _SRP_N
    premaster = pow(base, a_int + u * x, _SRP_N)
    session_key = _sha256(_pad_int(premaster))
    hash_n = _sha256(_pad_int(_SRP_N))
    hash_g = _sha256(_pad_int(_SRP_G))
    xor_hashes = bytes(left ^ right for left, right in zip(hash_n, hash_g))
    m1 = _sha256(
        xor_hashes,
        _sha256(username.encode("utf-8")),
        salt,
        a_public,
        b_padded,
        session_key,
    )
    m2 = _sha256(a_public, m1, session_key)
    return _SrpExchange(a_public=a_public, m1=m1, m2=m2, session_key=session_key)


def _negotiation_digest(sp: str, spd: bytes | None, sc: bytes | None) -> bytes:
    """The running transcript hash AltSign feeds before checking "np"."""
    digest = hashlib.sha256()
    digest.update(b"s2k,s2k_fo||")
    if sp:
        digest.update(sp.encode("utf-8"))
    digest.update(b"|")
    if spd is not None:
        digest.update(struct.pack("<I", len(spd)))
        digest.update(spd)
    digest.update(b"|")
    if sc is not None:
        digest.update(struct.pack("<I", len(sc)))
        digest.update(sc)
    digest.update(b"|")
    return digest.digest()


def _expected_negotiation_hmac(
    session_key: bytes,
    sp: str,
    spd: bytes | None,
    sc: bytes | None,
) -> bytes:
    hmac_key = hmac.new(session_key, b"HMAC key:", hashlib.sha256).digest()
    return hmac.new(hmac_key, _negotiation_digest(sp, spd, sc), hashlib.sha256).digest()


def _session_derived_key(session_key: bytes, name: str) -> bytes:
    return hmac.new(session_key, name.encode("utf-8"), hashlib.sha256).digest()


def _decrypt_login_data(session_key: bytes, spd: bytes) -> bytes:
    """AES-256-CBC (PKCS7) decryption of the "spd" login plist."""
    key = _session_derived_key(session_key, "extra data key:")
    iv = _session_derived_key(session_key, "extra data iv:")[:16]
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(spd) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    try:
        return unpadder.update(padded) + unpadder.finalize()
    except ValueError as exc:
        raise AuthError("The Grand Slam login data could not be decrypted.") from exc


def _decrypt_app_token(sk: bytes, encrypted: bytes) -> bytes:
    """AES-GCM decryption of the "et" app token blob ("XYZ" format)."""
    if len(encrypted) < 35:
        raise AuthError("The Grand Slam app token blob is truncated.")
    if encrypted[:3] != b"XYZ":
        raise AuthError("The Grand Slam app token blob has an unknown version.")
    iv = encrypted[3:19]
    tag = encrypted[-16:]
    ciphertext = encrypted[19:-16]
    decryptor = Cipher(algorithms.AES(sk), modes.GCM(iv, tag)).decryptor()
    decryptor.authenticate_additional_data(encrypted[:3])
    try:
        return decryptor.update(ciphertext) + decryptor.finalize()
    except InvalidTag as exc:
        raise AuthError("The Grand Slam app token failed authentication.") from exc


def _app_tokens_checksum(sk: bytes, adsid: str, apps: Sequence[str]) -> bytes:
    """ALTCreateAppTokensChecksum: HMAC-SHA256 over "apptokens"+adsid+apps."""
    digest = hmac.new(sk, b"apptokens", hashlib.sha256)
    digest.update(adsid.encode("utf-8"))
    for app in apps:
        digest.update(app.encode("utf-8"))
    return digest.digest()


# ------------------------------------------------------- plist plumbing


def _parse_plist(data: bytes, context: str) -> dict[str, object]:
    try:
        parsed = plistlib.loads(data)
    except (plistlib.InvalidFileException, ValueError) as exc:
        raise AuthError(f"Apple's Grand Slam {context} is not a valid plist.") from exc
    if not isinstance(parsed, dict):
        raise AuthError(f"Apple's Grand Slam {context} is not a plist dictionary.")
    return parsed


def _plist_bytes(container: Mapping[str, object], key: str, context: str) -> bytes:
    value = container.get(key)
    if not isinstance(value, bytes):
        raise AuthError(f"The Grand Slam {context} has no valid '{key}' data.")
    return value


def _plist_bytes_or_none(container: Mapping[str, object], key: str) -> bytes | None:
    value = container.get(key)
    return value if isinstance(value, bytes) else None


def _plist_str(container: Mapping[str, object], key: str, context: str) -> str:
    value = container.get(key)
    if not isinstance(value, str):
        raise AuthError(f"The Grand Slam {context} has no valid '{key}' string.")
    return value


def _plist_int(container: Mapping[str, object], key: str, context: str) -> int:
    value = container.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise AuthError(f"The Grand Slam {context} has no valid '{key}' integer.")
    return value


def _plist_mapping(container: Mapping[str, object], key: str, context: str) -> dict[str, object]:
    value = container.get(key)
    if not isinstance(value, dict):
        raise AuthError(f"The Grand Slam {context} has no valid '{key}' dictionary.")
    return value


def _status_error_code(container: Mapping[str, object]) -> tuple[int, str]:
    """Return (ec, em) from a nested Status dictionary or a flat plist.

    The main GSA endpoint nests ec/em under "Status"; the 2FA validate
    endpoint answers with a flat plist (AltSign reads the top level,
    SideStore checks both shapes).
    """
    status: object = container.get("Status")
    source: Mapping[str, object] = container
    if isinstance(status, dict):
        source = status
    code_value: object = source.get("ec")
    if isinstance(code_value, int) and not isinstance(code_value, bool):
        code = code_value
    elif isinstance(code_value, str) and code_value.lstrip("-").isdigit():
        code = int(code_value)
    else:
        code = 0
    message_value: object = source.get("em")
    message = message_value if isinstance(message_value, str) else ""
    return code, message


def _raise_for_status(container: Mapping[str, object], context: str) -> None:
    """Map Grand Slam Status error codes onto the error taxonomy."""
    code, message = _status_error_code(container)
    if code == 0:
        return
    detail = f" ({message})" if message else ""
    if code == GSA_ERR_INCORRECT_CREDENTIALS:
        raise AuthError(
            "Apple rejected the Apple ID or password." + detail,
            hint="Check the Apple ID and password, then run: sideload auth login",
        )
    if code == GSA_ERR_INCORRECT_SECURITY_CODE:
        raise TwoFactorError("Apple rejected the two factor security code." + detail)
    if code == -80009:
        raise AuthError(
            "Apple rejected this Mac's anisette data (MID is invalid)." + detail,
            hint=(
                "sign in with an Apple ID once in System Settings so this Mac "
                "is provisioned, then retry"
            ),
        )
    raise AuthError(f"Grand Slam authentication failed with Apple error {code}{detail} in {context}.")


def _cpd_from_data(data: AnisetteData, client_time: str) -> dict[str, object]:
    """The GSA client parameter dictionary from one anisette set."""
    return {
        "bootstrap": True,
        "icscrec": True,
        "loc": data.locale,
        "pbe": False,
        "prkgen": True,
        "svct": "iCloud",
        "X-Apple-I-Client-Time": client_time,
        "X-Apple-Locale": data.locale,
        "X-Apple-I-TimeZone": data.timezone,
        "X-Apple-I-MD": data.one_time_password,
        "X-Apple-I-MD-LU": data.local_user_id,
        "X-Apple-I-MD-M": data.machine_id,
        "X-Apple-I-MD-RINFO": data.routing_info,
        "X-Mme-Device-Id": data.device_unique_id,
        "X-Apple-I-SRL-NO": data.device_serial,
    }


def build_cpd(anisette: AnisetteProvider, client_time: str) -> dict[str, object]:
    """Build the GSA client parameter dictionary ("cpd").

    Exact dict, verified in ALTAppleAPI+Authentication.m:
    {"bootstrap": true, "icscrec": true, "loc": <locale>,
     "pbe": false, "prkgen": true, "svct": "iCloud",
     "X-Apple-I-Client-Time": <ISO8601>, "X-Apple-Locale": <locale>,
     "X-Apple-I-TimeZone": <tz abbreviation>, "X-Apple-I-MD": <otp>,
     "X-Apple-I-MD-LU": <local user id>, "X-Apple-I-MD-M": <machine id>,
     "X-Apple-I-MD-RINFO": <routing info>, "X-Mme-Device-Id": <udid>,
     "X-Apple-I-SRL-NO": <serial>}
    """
    data = anisette.get_anisette()
    return _cpd_from_data(data, client_time)


@dataclass(frozen=True)
class _LoginState:
    """Everything the complete step yields for one SRP round."""

    adsid: str
    idms_token: str
    sk: bytes
    challenge: bytes
    first_name: str
    last_name: str
    needs_two_factor: bool


class GrandSlamClient:
    """Performs Grand Slam login and returns a usable AppleSession."""

    def __init__(self, anisette: AnisetteProvider) -> None:
        """Store the anisette provider and prepare an HTTP session.

        The HTTP client must keep cookies for the duration of one login
        flow and support XML plist bodies.
        """
        self.anisette = anisette
        self.http = requests.Session()

    def authenticate(
        self,
        email: str,
        password: str,
        security_code_provider: Callable[[], str | None],
    ) -> AppleSession:
        """Run the full login: init, complete, optional 2FA, apptokens.

        Args:
            email: the Apple ID email address.
            password: the Apple ID password; used only in memory.
            security_code_provider: called when Apple requires 2FA; it
                must return a six digit code, or None to abort.

        Returns:
            AppleSession with dsid, gs token, expiry, and account.

        Raises:
            AuthError: wrong credentials or protocol failure.
            TwoFactorError: the security code was rejected.
        """
        attempts_used = 0
        while True:
            login = self._login_round(email, password)
            if not login.needs_two_factor:
                return self._request_app_session(email, login)
            self._request_two_factor_push(login.adsid, login.idms_token)
            validated = False
            while attempts_used < MAX_TWO_FACTOR_ATTEMPTS:
                code = security_code_provider()
                if code is None:
                    raise TwoFactorError(
                        "Apple requires a two factor security code, but none was provided.",
                        hint="Run: sideload auth login and enter the code sent to your devices",
                    )
                attempts_used += 1
                if self._validate_security_code(login.adsid, login.idms_token, code):
                    validated = True
                    break
            if not validated:
                raise TwoFactorError(
                    f"Apple rejected the two factor security code {MAX_TWO_FACTOR_ATTEMPTS} times.",
                    hint="Run: sideload auth login and request a fresh code",
                )
            # The account is trusted now; repeat the SRP exchange.

    # ------------------------------------------------------------ rounds

    def _login_round(self, email: str, password: str) -> _LoginState:
        """One init plus complete SRP exchange."""
        data, cpd = self._client_parameters()
        a = secrets.token_bytes(_SRP_PRIVATE_BYTES)
        init_body: dict[str, object] = {
            "o": "init",
            "u": email,
            "ps": ["s2k", "s2k_fo"],
            "A2k": _srp_public_ephemeral(a),
            "cpd": cpd,
        }
        init_response = self._post_plist(init_body, self._gsa_headers(data))
        sp = _plist_str(init_response, "sp", "init response")
        challenge = _plist_str(init_response, "c", "init response")
        salt = _plist_bytes(init_response, "s", "init response")
        iterations = _plist_int(init_response, "i", "init response")
        b = _plist_bytes(init_response, "B", "init response")

        password_key = _srp_password_key(password, salt, iterations, sp)
        exchange = _srp_client_challenge(email, password_key, salt, a, b)

        data_complete, cpd_complete = self._client_parameters()
        complete_body: dict[str, object] = {
            "o": "complete",
            "u": email,
            "c": challenge,
            "M1": exchange.m1,
            "cpd": cpd_complete,
        }
        complete_response = self._post_plist(
            complete_body, self._gsa_headers(data_complete)
        )

        server_proof = _plist_bytes(complete_response, "M2", "complete response")
        if not hmac.compare_digest(server_proof, exchange.m2):
            raise AuthError("The Grand Slam server proof did not match; the handshake failed.")
        spd = _plist_bytes(complete_response, "spd", "complete response")
        sc = _plist_bytes_or_none(complete_response, "sc")
        negotiation = _plist_bytes(complete_response, "np", "complete response")
        expected_negotiation = _expected_negotiation_hmac(exchange.session_key, sp, spd, sc)
        if not hmac.compare_digest(negotiation, expected_negotiation):
            raise AuthError("The Grand Slam negotiation hash did not match; the handshake failed.")

        login_plist = _parse_plist(
            _decrypt_login_data(exchange.session_key, spd), "login response"
        )
        adsid = _plist_str(login_plist, "adsid", "login response")
        idms_token = _plist_str(login_plist, "GsIdmsToken", "login response")
        sk = _plist_bytes(login_plist, "sk", "login response")
        session_challenge = _plist_bytes(login_plist, "c", "login response")
        first_name = login_plist.get("fn")
        last_name = login_plist.get("ln")

        status: object = complete_response.get("Status")
        au = ""
        if isinstance(status, dict):
            au_value: object = status.get("au")
            au = au_value if isinstance(au_value, str) else ""
        if au == "trustedDeviceSecondaryAuth":
            needs_two_factor = True
        elif au == "":
            needs_two_factor = False
        else:
            raise AuthError(
                f"Apple requires an authentication step sideload does not support: {au}"
            )

        return _LoginState(
            adsid=adsid,
            idms_token=idms_token,
            sk=sk,
            challenge=session_challenge,
            first_name=first_name if isinstance(first_name, str) else "",
            last_name=last_name if isinstance(last_name, str) else "",
            needs_two_factor=needs_two_factor,
        )

    def _request_app_session(self, email: str, login: _LoginState) -> AppleSession:
        """The apptokens step: trade sk for the com.apple.gs.xcode.auth token."""
        data, cpd = self._client_parameters()
        apps = [GSA_APP_NAME]
        checksum = _app_tokens_checksum(login.sk, login.adsid, apps)
        body: dict[str, object] = {
            "o": "apptokens",
            "u": login.adsid,
            "app": apps,
            "c": login.challenge,
            "t": login.idms_token,
            "checksum": checksum,
            "cpd": cpd,
        }
        response = self._post_plist(body, self._gsa_headers(data))
        encrypted = _plist_bytes(response, "et", "apptokens response")
        token_plist = _parse_plist(_decrypt_app_token(login.sk, encrypted), "app token response")
        tokens = _plist_mapping(token_plist, "t", "app token response")
        entry_value: object = tokens.get(GSA_APP_NAME)
        if not isinstance(entry_value, dict):
            raise AuthError(f"The app token response has no entry for {GSA_APP_NAME}.")
        entry: dict[str, object] = entry_value
        gs_token = _plist_str(entry, "token", "app token response")
        expiry_ms = _plist_int(entry, "expiry", "app token response")
        account = Account(
            first_name=login.first_name,
            last_name=login.last_name,
            email=email,
            dsid=login.adsid,
        )
        return AppleSession(
            dsid=login.adsid,
            gs_token=gs_token,
            token_expiry=datetime.fromtimestamp(expiry_ms / 1000, tz=UTC),
            account=account,
        )

    # ---------------------------------------------------------- 2FA

    def _request_two_factor_push(self, adsid: str, idms_token: str) -> None:
        """GET /auth/verify/trusteddevice to push a code to trusted devices."""
        headers = self._two_factor_headers(adsid, idms_token)
        response = self._get(GSA_TWO_FACTOR_TRIGGER_URL, headers)
        if not 200 <= response.status_code < 300:
            raise AuthError(
                f"Apple's trusted device code push failed with HTTP {response.status_code}."
            )

    def _validate_security_code(self, adsid: str, idms_token: str, code: str) -> bool:
        """GET /grandslam/GsService2/validate with the security-code header.

        Returns False for error -21669 (wrong code, ask again), True for
        success, and raises AuthError for any other Apple error.
        """
        headers = self._two_factor_headers(adsid, idms_token)
        headers["security-code"] = code
        response = self._get(GSA_TWO_FACTOR_VALIDATE_URL, headers)
        if response.status_code == 204:
            return True
        if response.status_code != 200:
            raise AuthError(
                f"Apple's security code validation failed with HTTP {response.status_code}."
            )
        container = _parse_plist(response.content, "security code response")
        error_code, message = _status_error_code(container)
        if error_code == 0:
            return True
        if error_code == GSA_ERR_INCORRECT_SECURITY_CODE:
            return False
        detail = f" ({message})" if message else ""
        raise AuthError(f"Apple rejected the security code with error {error_code}{detail}.")

    def _two_factor_headers(self, adsid: str, idms_token: str) -> dict[str, str]:
        """The Xcode/anisette header set AltSign sends on 2FA requests."""
        data = self.anisette.get_anisette()
        identity = f"{adsid}:{idms_token}"
        encoded = base64.b64encode(identity.encode("utf-8")).decode("ascii")
        return {
            "Content-Type": "text/x-xml-plist",
            "User-Agent": XCODE_USER_AGENT,
            "Accept": "text/x-xml-plist",
            "Accept-Language": "en-us",
            "X-Apple-App-Info": XCODE_APP_INFO,
            "X-Xcode-Version": XCODE_VERSION,
            _XCODE_IDENTITY_TOKEN_PREFIX: encoded,
            "X-Apple-I-MD-M": data.machine_id,
            "X-Apple-I-MD": data.one_time_password,
            "X-Apple-I-MD-LU": data.local_user_id,
            "X-Apple-I-MD-RINFO": str(data.routing_info),
            "X-Mme-Device-Id": data.device_unique_id,
            "X-MMe-Client-Info": data.device_description,
            "X-Apple-I-Client-Time": data.client_time,
            "X-Apple-Locale": data.locale,
            "X-Apple-I-TimeZone": data.timezone,
        }

    # ---------------------------------------------------------- plumbing

    def _client_parameters(self) -> tuple[AnisetteData, dict[str, object]]:
        """One fresh anisette set plus the cpd built from it.

        The OTP is one time use, so every Grand Slam request fetches a
        fresh set (DESIGN.md section 4.1).
        """
        data = self.anisette.get_anisette()
        return data, _cpd_from_data(data, data.client_time)

    @staticmethod
    def _gsa_headers(data: AnisetteData) -> dict[str, str]:
        """The four HTTP headers AltSign sends on GSA plist requests."""
        return {
            "Content-Type": "text/x-xml-plist",
            "X-MMe-Client-Info": data.device_description,
            "Accept": "*/*",
            "User-Agent": GSA_USER_AGENT,
        }

    def _post_plist(
        self,
        body: dict[str, object],
        headers: dict[str, str],
    ) -> dict[str, object]:
        """POST one GSA XML plist request and return the Response dict."""
        payload = plistlib.dumps(
            {"Header": {"Version": GSA_PROTOCOL_VERSION}, "Request": body},
            fmt=plistlib.FMT_XML,
        )
        try:
            response = self.http.post(
                GSA_ENDPOINT,
                data=payload,
                headers=headers,
                timeout=GSA_TIMEOUT,
                allow_redirects=False,
            )
        except requests.RequestException as exc:
            raise AuthError(f"Could not reach Apple's Grand Slam service: {exc}") from exc
        if response.status_code == 429:
            raise AuthError(
                "Apple is rate limiting sign in attempts from this network.",
                hint=(
                    "wait 30 to 60 minutes, then try once; every retry now "
                    "extends the block"
                ),
            )
        if response.status_code != 200:
            raise AuthError(
                f"Apple's Grand Slam service answered HTTP {response.status_code}."
            )
        container = _parse_plist(response.content, "response")
        inner_value: object = container.get("Response")
        if not isinstance(inner_value, dict):
            raise AuthError("The Grand Slam response has no Response dictionary.")
        _raise_for_status(inner_value, "response")
        return inner_value

    def _get(self, url: str, headers: dict[str, str]) -> requests.Response:
        """GET a Grand Slam 2FA endpoint with the given headers."""
        try:
            return self.http.get(
                url, headers=headers, timeout=GSA_TIMEOUT, allow_redirects=False
            )
        except requests.RequestException as exc:
            raise AuthError(f"Could not reach Apple's Grand Slam service: {exc}") from exc
