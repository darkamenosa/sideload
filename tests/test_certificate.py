"""Offline tests for the certificate signing path (--p12 + --profile).

No Apple ID, no network, no real Keychain, no device: the developer
service, anisette, and auth modules are patched to raise (proving the
path never touches them), the KeychainStore and the signer are in
memory doubles, and the provisioning profile is a real CMS signed
plist built with cryptography and decoded through the real
"security cms" tool. The IPA work (extract, rewrite, embed, repack)
runs for real and the output archive is opened to check its contents.
"""

from __future__ import annotations

import getpass
import plistlib
import zipfile
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7, pkcs12
from cryptography.x509.oid import NameOID

from sideload import cache as cache_mod
from sideload import config, errors
from sideload import keychain as keychain_mod
from sideload.apple import anisette as anisette_mod
from sideload.apple import auth as auth_mod
from sideload.apple import developer as developer_mod
from sideload.cli import build_parser, main
from sideload.device import installer as installer_mod
from sideload.device import usbmux as usbmux_mod
from sideload.signing import certificate as certificate_mod
from sideload.signing import entitlements as entitlements_mod
from sideload.signing import signer as signer_mod

TEAM = "TEAM123"
PROFILE_BUNDLE_ID = "com.example.resigned"
ORIGINAL_BUNDLE_ID = "com.example.original"
UDID = "00008101-000000000000000E"
PASSPHRASE = "test-p12-passphrase"
IDENTITY_NAME = "Apple Development: cert@example.com (TEAM123)"
PROFILE_UUID = "CAFE0000-0000-0000-0000-000000000001"


# ------------------------------------------------------------- fixtures


@pytest.fixture(scope="session")
def cert_material() -> SimpleNamespace:
    """A self signed developer certificate plus an encrypted .p12,
    both generated locally with cryptography (no Apple involved).
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, IDENTITY_NAME)]
    )
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2025, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2049, 1, 1, tzinfo=UTC))
        .sign(key, hashes.SHA256())
    )
    p12 = pkcs12.serialize_key_and_certificates(
        name=b"sideload-test",
        key=key,
        cert=certificate,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(
            PASSPHRASE.encode("utf-8")
        ),
    )
    return SimpleNamespace(
        key=key,
        certificate=certificate,
        cert_der=certificate.public_bytes(serialization.Encoding.DER),
        p12=p12,
    )


def build_profile(
    cert_material: SimpleNamespace,
    *,
    bundle_id: str = PROFILE_BUNDLE_ID,
    days: float = 7.0,
    devices: Sequence[str] = (UDID,),
    developer_certificates: Sequence[bytes] | None = None,
    uuid: str = PROFILE_UUID,
) -> bytes:
    """A real CMS signed .mobileprovision (security cms decodes it)."""
    now = datetime.now(UTC)
    plist = {
        "Name": "Certificate Fixture Profile",
        "UUID": uuid,
        "TeamIdentifier": [TEAM],
        "CreationDate": now,
        "ExpirationDate": now + timedelta(days=days),
        "Entitlements": {
            "application-identifier": f"{TEAM}.{bundle_id}",
            "get-task-allow": True,
            "com.apple.developer.team-identifier": TEAM,
        },
        "ProvisionedDevices": list(devices),
        "DeveloperCertificates": (
            list(developer_certificates)
            if developer_certificates is not None
            else [cert_material.cert_der]
        ),
        "LocalProvision": True,
    }
    return (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(plistlib.dumps(plist))
        .add_signer(cert_material.certificate, cert_material.key, hashes.SHA256())
        .sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary])
    )


def write_ipa(
    path: Path, bundle_id: str = ORIGINAL_BUNDLE_ID, *, extension: str | None = None
) -> Path:
    """A minimal but structurally real IPA (Payload/<app>/ with a Mach-O)."""
    entries: dict[str, bytes] = {
        "Payload/App.app/Info.plist": plistlib.dumps(
            {"CFBundleIdentifier": bundle_id, "CFBundleExecutable": "App"}
        ),
        "Payload/App.app/App": b"\xcf\xfa\xed\xfe" + b"\x00" * 28,
    }
    if extension is not None:
        entries[f"Payload/App.app/PlugIns/{extension}.appex/Info.plist"] = (
            plistlib.dumps(
                {
                    "CFBundleIdentifier": f"{bundle_id}.{extension}",
                    "CFBundleExecutable": extension,
                }
            )
        )
        entries[f"Payload/App.app/PlugIns/{extension}.appex/{extension}"] = (
            b"\xcf\xfa\xed\xfe" + b"\x00" * 28
        )
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in entries.items():
            info = zipfile.ZipInfo(name, date_time=(2025, 1, 1, 0, 0, 0))
            archive.writestr(info, data)
    return path


# --------------------------------------------------------------- fakes


@dataclass
class ImportCall:
    p12_path: str
    passphrase: str
    identity_note: str


class FakeCertificateKeychain:
    """KeychainStore double: records the import, returns the identity.

    The real import_identity feeds the passphrase to the security CLI
    on stdin, so recording it here also proves the pipeline hands the
    secret only to that one call.
    """

    imports: list[ImportCall] = []  # noqa: RUF012 - shared fake state

    def import_identity(
        self, p12_path: str, p12_password: str, identity_note: str
    ) -> str:
        FakeCertificateKeychain.imports.append(
            ImportCall(p12_path, p12_password, identity_note)
        )
        return IDENTITY_NAME


class FakeSigner:
    """Signer double recording sign calls; verification passes."""

    signed: list[object] = []  # noqa: RUF012 - shared fake state

    def __init__(self) -> None:
        return None

    def sign_bundle(
        self,
        bundle: object,
        entitlements_by_path: dict[str, dict[str, object]],
        identity: object,
    ) -> None:
        FakeSigner.signed.append((bundle, entitlements_by_path, identity))

    def verify_bundle(self, bundle: object) -> list[str]:
        return []


class FakeResult:
    """Minimal stand in for subprocess.CompletedProcess[str]."""

    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class FakeRunner:
    """Routes device tool invocations to scripted outputs."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.by_tool: dict[str, object] = {}

    def script(self, tool: str, result: object) -> None:
        self.by_tool[tool] = result

    def __call__(
        self, cmd: Sequence[str], timeout: float | None = None
    ) -> FakeResult:
        self.calls.append(list(cmd))
        name = Path(cmd[0]).name
        entry = self.by_tool.get(name)
        if entry is None:
            return FakeResult(returncode=0, stdout="", stderr="")
        if callable(entry):
            callable_entry = entry  # type: ignore[assignment]
            return callable_entry(list(cmd))
        assert isinstance(entry, FakeResult)
        return entry


def script_one_device(runner: FakeRunner, *, paired: bool = True) -> None:
    """One healthy scripted iPhone for the transport layer."""
    runner.script("idevice_id", FakeResult(0, UDID + "\n"))

    def ideviceinfo(cmd: list[str]) -> FakeResult:
        args = cmd[1:]
        domain = args[args.index("-q") + 1] if "-q" in args else None
        key = args[args.index("-k") + 1] if "-k" in args else None
        values = {
            (None, "DeviceName"): "iPhone 12",
            (None, "ProductType"): "iPhone12,3",
            (None, "ProductVersion"): "17.6.1",
            (usbmux_mod.DEVELOPER_MODE_DOMAIN, usbmux_mod.DEVELOPER_MODE_KEY): "Enabled",
        }
        if (domain, key) in values:
            return FakeResult(0, values[(domain, key)] + "\n")
        return FakeResult(0, "", "")

    runner.script("ideviceinfo", ideviceinfo)
    if paired:
        runner.script(
            "idevicepair", FakeResult(0, f"SUCCESS: Validated pairing with device {UDID}\n")
        )
    else:
        runner.script(
            "idevicepair", FakeResult(255, f"ERROR: Device {UDID} is not paired\n")
        )


def script_installer(runner: FakeRunner) -> None:
    """ideviceinstaller that reports a successful install."""

    def handle(cmd: list[str]) -> FakeResult:
        if "--version" in cmd:
            return FakeResult(0, "ideviceinstaller 1.2.0\n")
        return FakeResult(
            0,
            "Copying 'app.ipa' to device... DONE.\n"
            "\rInstall: CreatingStagingDirectory (10%)"
            "\r\rInstall: VerifyingApplication"
            "\r\rInstall: Complete\n",
        )

    runner.script("ideviceinstaller", handle)


# -------------------------------------------------------------- helpers


@pytest.fixture()
def home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    state = tmp_path / "state"
    monkeypatch.setenv(config.ENV_SIDELOAD_HOME, str(state))
    return state


@pytest.fixture()
def cert_stack(monkeypatch: pytest.MonkeyPatch, home: Path) -> None:
    """In memory keychain and signer plus Apple modules that raise."""
    FakeCertificateKeychain.imports = []
    FakeSigner.signed = []
    monkeypatch.setattr(keychain_mod, "KeychainStore", FakeCertificateKeychain)
    monkeypatch.setattr(signer_mod, "KeychainSigner", FakeSigner)
    monkeypatch.setattr(getpass, "getpass", lambda prompt: PASSPHRASE)

    def _no_apple(*args: object, **kwargs: object) -> object:
        raise AssertionError("the certificate path must not touch Apple")

    monkeypatch.setattr(developer_mod, "DeveloperServiceClient", _no_apple)
    monkeypatch.setattr(anisette_mod, "AnisetteProvider", _no_apple)
    monkeypatch.setattr(auth_mod, "GrandSlamClient", _no_apple)


def write_inputs(
    tmp_path: Path,
    cert_material: SimpleNamespace,
    *,
    profile_bytes: bytes | None = None,
    ipa_bundle_id: str = ORIGINAL_BUNDLE_ID,
    extension: str | None = None,
    profile_name: str = "dev.mobileprovision",
) -> tuple[Path, Path, Path]:
    """Write the fixture IPA, p12, and profile into tmp_path."""
    ipa = write_ipa(tmp_path / "app.ipa", ipa_bundle_id, extension=extension)
    p12 = tmp_path / "dev.p12"
    p12.write_bytes(cert_material.p12)
    profile = tmp_path / profile_name
    profile.write_bytes(
        profile_bytes if profile_bytes is not None else build_profile(cert_material)
    )
    return ipa, p12, profile


def read_output_info(output: Path) -> tuple[dict[str, object], bytes]:
    """Open the signed IPA: (main Info.plist, embedded profile bytes)."""
    with zipfile.ZipFile(output) as archive:
        info = plistlib.loads(archive.read("Payload/App.app/Info.plist"))
        return info, archive.read("Payload/App.app/embedded.mobileprovision")


# ------------------------------------------------- passphrase handling


def test_read_p12_passphrase_uses_getpass(monkeypatch: pytest.MonkeyPatch) -> None:
    prompts: list[str] = []

    def fake_getpass(prompt: str) -> str:
        prompts.append(prompt)
        return "secret-value"

    monkeypatch.setattr(getpass, "getpass", fake_getpass)
    assert certificate_mod.read_p12_passphrase(Path("dev.p12")) == "secret-value"
    assert prompts == ["p12 passphrase for dev.p12: "]


def test_read_p12_passphrase_eof_is_usage_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_eof(prompt: str) -> str:
        raise EOFError

    monkeypatch.setattr(getpass, "getpass", raise_eof)
    with pytest.raises(errors.UsageError):
        certificate_mod.read_p12_passphrase(Path("dev.p12"))


# --------------------------------------------------------- parser flags


def test_parser_accepts_p12_and_profile_flags() -> None:
    parser = build_parser()
    args = parser.parse_args(
        ["sign", "x.ipa", "--p12", "dev.p12", "--profile", "dev.mobileprovision"]
    )
    assert args.p12 == "dev.p12"
    assert args.profile == "dev.mobileprovision"
    args = parser.parse_args(
        ["install", "x.ipa", "--udid", "U", "--p12", "dev.p12", "--profile", "dev.mobileprovision"]
    )
    assert args.p12 == "dev.p12"
    assert args.profile == "dev.mobileprovision"
    assert args.udid == "U"


def test_sign_help_lists_the_certificate_flags(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["sign", "--help"])
    assert excinfo.value.code == 0
    text = capsys.readouterr().out
    assert "--p12 PATH" in text
    assert "--profile PATH" in text


# ----------------------------------------------------------- happy path


def test_certificate_sign_happy_path(
    home: Path,
    cert_stack: None,
    cert_material: SimpleNamespace,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Sign from a p12 plus profile with no Apple ID session stored at
    all: no network, no session load, and the output IPA really carries
    the profile bundle id and the embedded profile bytes.
    """
    ipa, p12, profile = write_inputs(tmp_path, cert_material)
    profile_bytes = profile.read_bytes()

    code = main(["sign", str(ipa), "--p12", str(p12), "--profile", str(profile)])

    assert code == 0
    out = capsys.readouterr().out
    assert f"team: {TEAM} (from the profile)" in out
    assert f"certificate: imported ({IDENTITY_NAME})" in out
    assert f"bundle id: {ORIGINAL_BUNDLE_ID} -> {PROFILE_BUNDLE_ID}" in out
    assert "profile expires:" in out
    assert f"output: {tmp_path / 'app.signed.ipa'}" in out

    # the identity import went through the keychain with the profile team
    assert FakeCertificateKeychain.imports == [
        ImportCall(str(p12), PASSPHRASE, TEAM)
    ]
    # the signer ran with the imported identity and profile entitlements
    assert FakeSigner.signed
    _bundle, entitlements_by_path, identity = FakeSigner.signed[0]
    assert "App" in entitlements_by_path
    assert identity.keychain_identity == IDENTITY_NAME
    assert identity.team_identifier == TEAM

    # the passphrase is never echoed anywhere
    captured = capsys.readouterr()
    assert PASSPHRASE not in captured.out
    assert PASSPHRASE not in captured.err

    # the output IPA is a real archive with the rewritten id and profile
    output = tmp_path / "app.signed.ipa"
    assert output.is_file()
    info, embedded = read_output_info(output)
    assert info["CFBundleIdentifier"] == PROFILE_BUNDLE_ID
    assert embedded == profile_bytes


def test_sign_with_certificate_injectable_collaborators(
    cert_material: SimpleNamespace, tmp_path: Path
) -> None:
    """The module accepts its collaborators directly, so callers can
    stay offline without any monkeypatching."""
    ipa, p12, profile = write_inputs(tmp_path, cert_material)
    store = FakeCertificateKeychain()
    backend = FakeSigner()
    outcome = certificate_mod.sign_with_certificate(
        ipa_path=ipa,
        p12_path=p12,
        profile_path=profile,
        output_path=tmp_path / "out.ipa",
        udid=None,
        prompt_passphrase=lambda path: PASSPHRASE,
        store=store,  # type: ignore[arg-type]
        backend=backend,  # type: ignore[arg-type]
    )
    assert outcome.signed_bundle_id == PROFILE_BUNDLE_ID
    assert outcome.original_bundle_id == ORIGINAL_BUNDLE_ID
    assert outcome.output_ipa == str(tmp_path / "out.ipa")
    assert outcome.profile.team_identifier == TEAM
    assert outcome.identity.keychain_identity == IDENTITY_NAME
    assert store.imports[0].passphrase == PASSPHRASE
    assert (tmp_path / "out.ipa").is_file()


# ------------------------------------------------------------- failures


def test_wrong_passphrase_exits_1(
    home: Path,
    cert_stack: None,
    cert_material: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(getpass, "getpass", lambda prompt: "wrong-passphrase")
    ipa, p12, profile = write_inputs(tmp_path, cert_material)

    code = main(["sign", str(ipa), "--p12", str(p12), "--profile", str(profile)])

    assert code == 1
    captured = capsys.readouterr()
    assert "could not unlock dev.p12" in captured.err
    assert "passphrase is wrong" in captured.err
    assert "wrong-passphrase" not in captured.out and "wrong-passphrase" not in captured.err
    # the wrong passphrase never reached the Keychain or the signer
    assert FakeCertificateKeychain.imports == []
    assert FakeSigner.signed == []


def test_expired_profile_exits_1(
    home: Path,
    cert_stack: None,
    cert_material: SimpleNamespace,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ipa, p12, profile = write_inputs(
        tmp_path, cert_material, profile_bytes=build_profile(cert_material, days=-1.0)
    )
    code = main(["sign", str(ipa), "--p12", str(p12), "--profile", str(profile)])
    assert code == 1
    captured = capsys.readouterr()
    assert "expired" in captured.err
    # no passphrase prompt and no keychain import for a dead profile
    assert FakeCertificateKeychain.imports == []
    assert FakeSigner.signed == []


def test_missing_p12_exits_2_before_prompt(
    home: Path,
    cert_stack: None,
    cert_material: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail(prompt: str) -> str:
        raise AssertionError("must not prompt when an input file is missing")

    monkeypatch.setattr(getpass, "getpass", fail)
    ipa, _p12, profile = write_inputs(tmp_path, cert_material)

    code = main(
        ["sign", str(ipa), "--p12", str(tmp_path / "nope.p12"), "--profile", str(profile)]
    )
    assert code == 2
    assert "p12 file not found" in capsys.readouterr().err


def test_missing_profile_exits_2(
    home: Path,
    cert_stack: None,
    cert_material: SimpleNamespace,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ipa, p12, _profile = write_inputs(tmp_path, cert_material)
    code = main(
        ["sign", str(ipa), "--p12", str(p12), "--profile", str(tmp_path / "nope.mobileprovision")]
    )
    assert code == 2
    assert "profile file not found" in capsys.readouterr().err


@pytest.mark.parametrize("argv", [["sign", "x.ipa", "--p12", "dev.p12"], ["install", "x.ipa", "--profile", "p.mobileprovision"]])
def test_p12_and_profile_must_be_passed_together(
    home: Path,
    cert_stack: None,
    cert_material: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    argv: list[str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Only one of the two flags is a usage error, before any prompt."""
    monkeypatch.setattr(getpass, "getpass", lambda prompt: PASSPHRASE)
    ipa, _p12, _profile = write_inputs(tmp_path, cert_material)
    argv = [str(ipa) if part == "x.ipa" else part for part in argv]
    code = main(argv)
    assert code == 2
    captured = capsys.readouterr()
    assert "--p12 and --profile must be passed together" in captured.err
    assert "hint:" in captured.err
    assert FakeCertificateKeychain.imports == []


def test_bundle_id_conflict_with_profile_exits_2(
    home: Path,
    cert_stack: None,
    cert_material: SimpleNamespace,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ipa, p12, profile = write_inputs(tmp_path, cert_material)
    code = main(
        [
            "sign",
            str(ipa),
            "--p12",
            str(p12),
            "--profile",
            str(profile),
            "--bundle-id",
            "com.example.other",
        ]
    )
    assert code == 2
    captured = capsys.readouterr()
    assert "conflicts with the profile" in captured.err
    assert "com.example.other" in captured.err
    assert PROFILE_BUNDLE_ID in captured.err
    assert FakeCertificateKeychain.imports == []


def test_bundle_id_matching_profile_is_accepted(
    home: Path,
    cert_stack: None,
    cert_material: SimpleNamespace,
    tmp_path: Path,
) -> None:
    ipa, p12, profile = write_inputs(tmp_path, cert_material)
    code = main(
        [
            "sign",
            str(ipa),
            "--p12",
            str(p12),
            "--profile",
            str(profile),
            "--bundle-id",
            PROFILE_BUNDLE_ID,
        ]
    )
    assert code == 0


def test_team_conflict_with_profile_exits_2(
    home: Path,
    cert_stack: None,
    cert_material: SimpleNamespace,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ipa, p12, profile = write_inputs(tmp_path, cert_material)
    code = main(
        ["sign", str(ipa), "--p12", str(p12), "--profile", str(profile), "--team", "OTHER"]
    )
    assert code == 2
    captured = capsys.readouterr()
    assert "does not match the profile team" in captured.err
    assert TEAM in captured.err


def test_certificate_not_in_profile_exits_1(
    home: Path,
    cert_stack: None,
    cert_material: SimpleNamespace,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    profile_bytes = build_profile(
        cert_material, developer_certificates=[b"\x30\x82another-certificate-der"]
    )
    ipa, p12, profile = write_inputs(tmp_path, cert_material, profile_bytes=profile_bytes)
    code = main(["sign", str(ipa), "--p12", str(p12), "--profile", str(profile)])
    assert code == 1
    captured = capsys.readouterr()
    assert "is not included in profile" in captured.err
    # nothing was imported or signed with a certificate the profile rejects
    assert FakeCertificateKeychain.imports == []
    assert FakeSigner.signed == []


def test_profile_without_certificates_exits_1(
    home: Path,
    cert_stack: None,
    cert_material: SimpleNamespace,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    profile_bytes = build_profile(cert_material, developer_certificates=[])
    ipa, p12, profile = write_inputs(tmp_path, cert_material, profile_bytes=profile_bytes)
    code = main(["sign", str(ipa), "--p12", str(p12), "--profile", str(profile)])
    assert code == 1
    assert "no DeveloperCertificates" in capsys.readouterr().err


# ------------------------------------------------------- install flows


def test_install_with_certificate_full_flow(
    home: Path,
    cert_stack: None,
    cert_material: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """install --p12 --profile needs no Apple ID session at all and
    still runs the regular device install afterwards."""
    runner = FakeRunner()
    monkeypatch.setattr(usbmux_mod, "_run_subprocess", runner)
    monkeypatch.setattr(installer_mod, "_run_subprocess", runner)
    script_one_device(runner)
    script_installer(runner)
    ipa, p12, profile = write_inputs(tmp_path, cert_material)

    code = main(["install", str(ipa), "--p12", str(p12), "--profile", str(profile)])

    assert code == 0
    out = capsys.readouterr().out
    assert f"bundle id: {ORIGINAL_BUNDLE_ID} -> {PROFILE_BUNDLE_ID}" in out
    assert "CreatingStagingDirectory (10%)" in out
    assert f"installed: {PROFILE_BUNDLE_ID}" in out
    # the device received the freshly signed artifact
    signed = ipa.with_name(ipa.stem + ".signed.ipa")
    install_call = next(call for call in runner.calls if call[-1] == str(signed))
    assert install_call[1:] == ["-u", UDID, "install", str(signed)]
    # the install is recorded for doctor, keyed by the profile team
    paths = config.get_paths()
    records = cache_mod.ResourceCache(paths).load_install_records(UDID)
    assert len(records) == 1
    assert records[0].resigned_bundle_id == PROFILE_BUNDLE_ID
    assert records[0].dsid == TEAM
    assert records[0].profile_uuid == PROFILE_UUID


def test_install_with_certificate_without_device_exits_1(
    home: Path,
    cert_stack: None,
    cert_material: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    runner = FakeRunner()
    monkeypatch.setattr(usbmux_mod, "_run_subprocess", runner)
    monkeypatch.setattr(installer_mod, "_run_subprocess", runner)
    runner.script("idevice_id", FakeResult(0, ""))
    ipa, p12, profile = write_inputs(tmp_path, cert_material)
    code = main(["install", str(ipa), "--p12", str(p12), "--profile", str(profile)])
    assert code == 1
    assert "no USB device is connected" in capsys.readouterr().err


def test_install_device_not_in_profile_exits_1(
    home: Path,
    cert_stack: None,
    cert_material: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    runner = FakeRunner()
    monkeypatch.setattr(usbmux_mod, "_run_subprocess", runner)
    monkeypatch.setattr(installer_mod, "_run_subprocess", runner)
    script_one_device(runner)
    profile_bytes = build_profile(cert_material, devices=("00008101-000000000000000E",))
    ipa, p12, profile = write_inputs(tmp_path, cert_material, profile_bytes=profile_bytes)
    code = main(["install", str(ipa), "--p12", str(p12), "--profile", str(profile)])
    assert code == 1
    captured = capsys.readouterr()
    assert "is not in profile" in captured.err
    assert FakeSigner.signed == []


def test_sign_only_skips_the_device_check(
    home: Path,
    cert_stack: None,
    cert_material: SimpleNamespace,
    tmp_path: Path,
) -> None:
    """sign with a profile that provisions no device at all: expiry
    and bundle id are still validated, the device check is not."""
    profile_bytes = build_profile(cert_material, devices=())
    ipa, p12, profile = write_inputs(tmp_path, cert_material, profile_bytes=profile_bytes)
    code = main(["sign", str(ipa), "--p12", str(p12), "--profile", str(profile)])
    assert code == 0
    info, _embedded = read_output_info(tmp_path / "app.signed.ipa")
    assert info["CFBundleIdentifier"] == PROFILE_BUNDLE_ID


# ----------------------------------------------------------- wildcards


def test_wildcard_profile_keeps_the_original_bundle_id(
    home: Path,
    cert_stack: None,
    cert_material: SimpleNamespace,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    profile_bytes = build_profile(cert_material, bundle_id="*")
    ipa, p12, profile = write_inputs(tmp_path, cert_material, profile_bytes=profile_bytes)
    code = main(["sign", str(ipa), "--p12", str(p12), "--profile", str(profile)])
    assert code == 0
    info, _embedded = read_output_info(tmp_path / "app.signed.ipa")
    assert info["CFBundleIdentifier"] == ORIGINAL_BUNDLE_ID
    out = capsys.readouterr().out
    assert f"bundle id: {ORIGINAL_BUNDLE_ID} -> {ORIGINAL_BUNDLE_ID}" in out


def test_wildcard_profile_honors_bundle_id_override(
    home: Path,
    cert_stack: None,
    cert_material: SimpleNamespace,
    tmp_path: Path,
) -> None:
    profile_bytes = build_profile(cert_material, bundle_id="*")
    ipa, p12, profile = write_inputs(tmp_path, cert_material, profile_bytes=profile_bytes)
    code = main(
        [
            "sign",
            str(ipa),
            "--p12",
            str(p12),
            "--profile",
            str(profile),
            "--bundle-id",
            "com.example.chosen",
        ]
    )
    assert code == 0
    info, _embedded = read_output_info(tmp_path / "app.signed.ipa")
    assert info["CFBundleIdentifier"] == "com.example.chosen"


def test_wildcard_profile_signs_extensions(
    home: Path,
    cert_stack: None,
    cert_material: SimpleNamespace,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    profile_bytes = build_profile(cert_material, bundle_id="*")
    ipa, p12, profile = write_inputs(
        tmp_path, cert_material, profile_bytes=profile_bytes, extension="Share"
    )
    code = main(["sign", str(ipa), "--p12", str(p12), "--profile", str(profile)])
    assert code == 0
    child_id = f"{ORIGINAL_BUNDLE_ID}.Share"
    out = capsys.readouterr().out
    assert f"extension: {child_id}" in out
    # the extension's Info.plist was rewritten and the profile embedded
    with zipfile.ZipFile(tmp_path / "app.signed.ipa") as archive:
        ext_info = plistlib.loads(
            archive.read("Payload/App.app/PlugIns/Share.appex/Info.plist")
        )
        assert ext_info["CFBundleIdentifier"] == child_id
        embedded = archive.read("Payload/App.app/PlugIns/Share.appex/embedded.mobileprovision")
    assert embedded == profile_bytes


def test_specific_profile_cannot_cover_extensions(
    home: Path,
    cert_stack: None,
    cert_material: SimpleNamespace,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """One specific profile never provisions a child bundle id, so the
    run fails before signing (and before the keychain import)."""
    ipa, p12, profile = write_inputs(tmp_path, cert_material, extension="Share")
    code = main(["sign", str(ipa), "--p12", str(p12), "--profile", str(profile)])
    assert code == 1
    captured = capsys.readouterr()
    assert "cannot cover the app extensions" in captured.err
    assert "wildcard profile" in captured.err
    assert FakeCertificateKeychain.imports == []
    assert FakeSigner.signed == []


# -------------------------------------------------------- p12 re-wrapping


def test_modern_p12_is_rewrapped_when_security_refuses_it(
    home: Path,
    cert_stack: None,
    cert_material: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Apple's security CLI rejects the modern p12 wrapping (AES plus
    SHA-256 MAC, what OpenSSL 3 exports) even with the correct
    passphrase; the pipeline must re-wrap the unlocked key and chain
    into the legacy form, import that, and still finish the sign.
    """
    attempts: list[bytes] = []

    class ReWrappingKeychain:
        def import_identity(
            self, p12_path: str, p12_password: str, identity_note: str
        ) -> str:
            data = Path(p12_path).read_bytes()
            attempts.append(data)
            if len(attempts) == 1 and data == cert_material.p12:
                raise errors.KeychainError(
                    "Could not import the signing identity into the Keychain: "
                    "security: SecKeychainItemImport: MAC verification failed "
                    "during PKCS12 import (wrong password?)"
                )
            return IDENTITY_NAME

    monkeypatch.setattr(keychain_mod, "KeychainStore", ReWrappingKeychain)
    ipa, p12, profile = write_inputs(tmp_path, cert_material)

    code = main(["sign", str(ipa), "--p12", str(p12), "--profile", str(profile)])

    assert code == 0
    captured = capsys.readouterr()
    assert "re-wrapped it locally" in captured.out
    # two import attempts: the original p12, then a different re-wrapped one
    assert len(attempts) == 2
    assert attempts[0] == cert_material.p12
    assert attempts[1] != cert_material.p12


def test_rewrap_import_bytes_roundtrip(
    cert_material: SimpleNamespace, tmp_path: Path
) -> None:
    """Direct module call against a keychain double that rejects the
    first import on MAC grounds: the second import must receive a p12
    that opens with the same passphrase and still carries the cert.
    """
    from cryptography.hazmat.primitives.serialization import pkcs12 as _pkcs12

    seen: list[bytes] = []

    class Store:
        def import_identity(
            self, p12_path: str, p12_password: str, identity_note: str
        ) -> str:
            data = Path(p12_path).read_bytes()
            seen.append(data)
            if len(seen) == 1:
                raise errors.KeychainError(
                    "Could not import the signing identity into the Keychain: "
                    "security: SecKeychainItemImport: MAC verification failed "
                    "during PKCS12 import (wrong password?)"
                )
            return IDENTITY_NAME

    ipa, p12, profile = write_inputs(tmp_path, cert_material)
    outcome = certificate_mod.sign_with_certificate(
        ipa_path=ipa,
        p12_path=p12,
        profile_path=profile,
        output_path=tmp_path / "out.ipa",
        udid=None,
        prompt_passphrase=lambda path: PASSPHRASE,
        store=Store(),  # type: ignore[arg-type]
        backend=FakeSigner(),  # type: ignore[arg-type]
    )
    assert outcome.identity.keychain_identity == IDENTITY_NAME
    assert len(seen) == 2
    assert seen[0] == cert_material.p12
    assert seen[1] != cert_material.p12
    _key, _cert, _cas = _pkcs12.load_key_and_certificates(seen[1], PASSPHRASE.encode())
    assert _cert is not None and _key is not None


def test_rewrap_gives_up_on_other_keychain_errors(
    cert_material: SimpleNamespace, tmp_path: Path
) -> None:
    """A non-format keychain failure (locked, denied) is not retried
    with a re-wrapped p12; the error surfaces unchanged.
    """

    class Store:
        def import_identity(
            self, p12_path: str, p12_password: str, identity_note: str
        ) -> str:
            raise errors.KeychainError("Could not import the signing identity: user denied")

    ipa, p12, profile = write_inputs(tmp_path, cert_material)
    with pytest.raises(errors.KeychainError, match="user denied"):
        certificate_mod.sign_with_certificate(
            ipa_path=ipa,
            p12_path=p12,
            profile_path=profile,
            output_path=tmp_path / "out.ipa",
            udid=None,
            prompt_passphrase=lambda path: PASSPHRASE,
            store=Store(),  # type: ignore[arg-type]
            backend=FakeSigner(),  # type: ignore[arg-type]
        )


def test_corrupt_p12_file_exits_1(
    home: Path,
    cert_stack: None,
    cert_material: SimpleNamespace,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ipa, p12, profile = write_inputs(tmp_path, cert_material)
    p12.write_bytes(b"this is not a p12 at all")
    code = main(["sign", str(ipa), "--p12", str(p12), "--profile", str(profile)])
    assert code == 1
    captured = capsys.readouterr()
    assert "could not unlock dev.p12" in captured.err
    assert FakeCertificateKeychain.imports == []


# ---------------------------------------------------------- entitlements


def test_dropped_entitlements_print_a_warning(
    home: Path,
    cert_stack: None,
    cert_material: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        entitlements_mod,
        "read_entitlements",
        lambda macho_path: {"com.apple.private.tcc": True},
    )
    ipa, p12, profile = write_inputs(tmp_path, cert_material)
    code = main(["sign", str(ipa), "--p12", str(p12), "--profile", str(profile)])
    assert code == 0
    out = capsys.readouterr().out
    assert "warning: entitlement 'com.apple.private.tcc' is not granted" in out
    assert "killed at launch by amfid" in out


def test_strict_entitlements_exits_1(
    home: Path,
    cert_stack: None,
    cert_material: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        entitlements_mod,
        "read_entitlements",
        lambda macho_path: {"com.apple.private.tcc": True},
    )
    ipa, p12, profile = write_inputs(tmp_path, cert_material)
    code = main(
        [
            "sign",
            str(ipa),
            "--p12",
            str(p12),
            "--profile",
            str(profile),
            "--strict-entitlements",
        ]
    )
    assert code == 1
    assert "error:" in capsys.readouterr().err
