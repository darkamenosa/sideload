"""macOS Keychain storage for the Apple session and the signing identity.

Nothing sensitive is ever written to disk in plaintext:

    session   a generic password in the user's login keychain holding
              base64 of a JSON blob {dsid, gs_token, token_expiry,
              account fields}. Base64 keeps the value free of quotes,
              apostrophes, and backslashes, so the stdin command parser
              can never mangle it.
              under service "dev.sideload.session", account = Apple ID
              email. The Apple ID password itself is never stored.
    identity  the developer certificate plus private key imported as a
              .p12 into the login keychain, trusted for /usr/bin/codesign
              via "security import -T /usr/bin/codesign".

Implementation contract (AUTH agent), all via the "security" CLI:

    set    security add-generic-password -a <email> -s <service> \
              -w <secret> -U <keychain>
    get    security find-generic-password -a <email> -s <service> -w
    delete security delete-generic-password -a <email> -s <service>

Keychain prompts: first "find" per terminal session may prompt for
keychain access; this is expected and documented in the CLI output.

The Apple ID password never passes through this module: the session
blob holds only the Grand Slam token material, and the token expiry is
stored as an ISO 8601 string so it survives restarts.

Ownership: AUTH agent. The SIGN agent consumes import/find/delete for
the signing identity only; the DEVICE agent never touches this module.
"""

from __future__ import annotations

import base64
import json
import re
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Final

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from sideload.errors import KeychainError
from sideload.models import Account, AppleSession, SigningIdentity

SERVICE_SESSION = "dev.sideload.session"
SERVICE_IDENTITY_NOTE = "dev.sideload.identity"

# The macOS security CLI and its "item not found" exit status.
SECURITY_TOOL: Final[str] = "/usr/bin/security"
EXIT_ITEM_NOT_FOUND: Final[int] = 44
_SUBPROCESS_TIMEOUT: Final[float] = 30.0

# The label shown in Keychain Access for the sideload session item.
_SESSION_LABEL: Final[str] = "sideload Apple session"

# Matches lines of "security find-identity -v -p codesigning" output:
#   1) 0123ABCD "Apple Development: user@example.com (TEAMID)" ...
_IDENTITY_LINE: Final[re.Pattern[str]] = re.compile(
    r"^\s*\d+\)\s+[0-9A-Fa-f]+\s+\"(?P<name>[^\"]+)\""
)
# The team identifier is the parenthesized suffix of the identity name.
_IDENTITY_TEAM_SUFFIX: Final[re.Pattern[str]] = re.compile(r"\(([^()\s]+)\)\s*$")

# A runner executes one "security <args>" invocation. Injectable so the
# test suite can run a fully offline in-memory keychain.
SecurityRunner = Callable[[list[str]], "subprocess.CompletedProcess[bytes]"]

# Interactive runner: one already-quoted "security" command line, fed on
# stdin so secrets never appear in the process argument vector.
StdinRunner = Callable[[str], "subprocess.CompletedProcess[bytes]"]


def _default_runner(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    """Run the real security CLI with captured output."""
    try:
        return subprocess.run(
            [SECURITY_TOOL, *args],
            capture_output=True,
            timeout=_SUBPROCESS_TIMEOUT,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        raise KeychainError(f"Could not run the macOS security tool: {exc}") from exc


def _default_stdin_runner(line: str) -> subprocess.CompletedProcess[bytes]:
    """Run one security command in interactive mode via stdin."""
    try:
        return subprocess.run(
            [SECURITY_TOOL, "-i"],
            input=(line + "\n").encode("utf-8"),
            capture_output=True,
            timeout=_SUBPROCESS_TIMEOUT,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        raise KeychainError(f"Could not run the macOS security tool: {exc}") from exc


def _quote_interactive(part: str) -> str:
    """Quote one argument for the security CLI stdin parser.

    That parser understands double quotes and backslash escapes, but not
    the shell "'\''" idiom (it mangles it), so shlex.quote is wrong here: an Apple ID
    such as o'brien@example.com would otherwise fail to store.
    """
    if "\n" in part or "\r" in part:
        raise KeychainError("a security command argument contains a newline")
    return '"' + part.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _stderr_text(result: subprocess.CompletedProcess[bytes]) -> str:
    text = result.stderr.decode("utf-8", errors="replace").strip()
    if not text:
        text = result.stdout.decode("utf-8", errors="replace").strip()
    return text or f"security exited with status {result.returncode}"


class KeychainStore:
    """Wrapper around the macOS "security" CLI for sideload secrets."""

    def __init__(
        self,
        keychain: str | None = None,
        runner: SecurityRunner | None = None,
        stdin_runner: StdinRunner | None = None,
    ) -> None:
        """Prepare the store.

        Args:
            keychain: optional path to a specific keychain file; when
                omitted the login keychain is used.
            runner: optional substitute for the security CLI, used by
                the offline test suite.
        """
        self.keychain = keychain
        self._runner: SecurityRunner = runner if runner is not None else _default_runner
        self._stdin_runner: StdinRunner = (
            stdin_runner if stdin_runner is not None else _default_stdin_runner
        )

    # ------------------------------------------------------------ session

    def save_session(self, email: str, session: AppleSession) -> None:
        """Persist the Grand Slam session as a generic password.

        Raises KeychainError if the security CLI fails or the user
        denies access.
        """
        payload = {
            "dsid": session.dsid,
            "gs_token": session.gs_token,
            "token_expiry": session.token_expiry.isoformat(),
            "account": {
                "first_name": session.account.first_name,
                "last_name": session.account.last_name,
                "email": session.account.email,
                "dsid": session.account.dsid,
            },
        }
        blob = "b64:" + base64.b64encode(
            json.dumps(payload).encode("utf-8")
        ).decode("ascii")
        args = [
            "add-generic-password",
            "-a",
            email,
            "-s",
            SERVICE_SESSION,
            "-l",
            _SESSION_LABEL,
            "-w",
            blob,
            "-U",
        ]
        result = self._run_interactive(args)
        if result.returncode != 0:
            raise KeychainError(
                f"Could not store the sideload session in the Keychain: {_stderr_text(result)}",
                hint="Allow Keychain access when macOS prompts for it",
            )

    def load_session(self, email: str) -> AppleSession | None:
        """Return the stored session for this Apple ID, or None.

        The caller is responsible for checking token expiry and raising
        SessionExpiredError; this method only reports what is stored.
        """
        args = ["find-generic-password", "-a", email, "-s", SERVICE_SESSION, "-w"]
        result = self._run(args)
        if result.returncode == EXIT_ITEM_NOT_FOUND:
            return None
        if result.returncode != 0:
            raise KeychainError(
                f"Could not read the sideload session from the Keychain: {_stderr_text(result)}",
                hint="Allow Keychain access when macOS prompts for it",
            )
        secret = result.stdout.decode("utf-8", errors="strict").rstrip("\n")
        if secret.startswith("b64:"):
            try:
                secret = base64.b64decode(secret[4:]).decode("utf-8")
            except (ValueError, UnicodeDecodeError) as exc:
                raise KeychainError(
                    "The stored sideload session is corrupt and could not be parsed.",
                    hint="Run: sideload auth logout, then sideload auth login",
                ) from exc
        try:
            data = json.loads(secret)
        except json.JSONDecodeError as exc:
            raise KeychainError(
                "The stored sideload session is corrupt and could not be parsed.",
                hint="Run: sideload auth logout, then sideload auth login",
            ) from exc
        if not isinstance(data, dict):
            raise KeychainError(
                "The stored sideload session has an unexpected format.",
                hint="Run: sideload auth logout, then sideload auth login",
            )
        return self._session_from_blob(email, data)

    def delete_session(self, email: str) -> bool:
        """Remove the stored session. Returns False when absent."""
        args = ["delete-generic-password", "-a", email, "-s", SERVICE_SESSION]
        result = self._run(args)
        if result.returncode == EXIT_ITEM_NOT_FOUND:
            return False
        if result.returncode != 0:
            raise KeychainError(
                f"Could not delete the sideload session from the Keychain: {_stderr_text(result)}"
            )
        return True

    @staticmethod
    def _session_from_blob(email: str, data: dict[str, object]) -> AppleSession:
        """Rebuild an AppleSession from the stored JSON blob."""
        dsid = _blob_str(data, "dsid")
        gs_token = _blob_str(data, "gs_token")
        expiry_text = _blob_str(data, "token_expiry")
        try:
            token_expiry = datetime.fromisoformat(expiry_text)
        except ValueError as exc:
            raise KeychainError(
                "The stored sideload session has an invalid token expiry.",
                hint="Run: sideload auth logout, then sideload auth login",
            ) from exc
        if token_expiry.tzinfo is None:
            token_expiry = token_expiry.replace(tzinfo=UTC)
        account_data = data.get("account")
        if not isinstance(account_data, dict):
            account_data = {}
        account_email = account_data.get("email")
        return AppleSession(
            dsid=dsid,
            gs_token=gs_token,
            token_expiry=token_expiry,
            account=_account_from_blob(email, dsid, account_data, account_email),
        )

    # ------------------------------------------------------------ identity

    def import_identity(
        self,
        p12_path: str,
        p12_password: str,
        identity_note: str,
    ) -> str:
        """Import a .p12 (certificate plus private key) into the login
        keychain, trusted for /usr/bin/codesign, and return the keychain
        identity name suitable for "codesign -s", for example
        "Apple Development: user@example.com (TEAMID)".

        The security CLI has no way to tag the imported item, so the
        identity is located by diffing "security find-identity" before
        and after the import; identity_note (usually the team id or the
        SERVICE_IDENTITY_NOTE marker) disambiguates when the import
        lands in an identity that already existed.
        """
        before = self._identity_names()
        args = ["import", p12_path, "-P", p12_password, "-T", "/usr/bin/codesign"]
        if self.keychain is not None:
            args.extend(["-k", self.keychain])
        result = self._run_interactive(args)
        if result.returncode != 0:
            raise KeychainError(
                f"Could not import the signing identity into the Keychain: {_stderr_text(result)}"
            )
        after = self._identity_names()
        new_names = sorted(after - before)
        if len(new_names) == 1:
            return new_names[0]
        tagged_new = [name for name in new_names if identity_note in name]
        if len(tagged_new) == 1:
            return tagged_new[0]
        tagged_existing = [name for name in sorted(after) if identity_note in name]
        if len(new_names) == 0 and len(tagged_existing) == 1:
            # The p12 matched an identity that was already present.
            return tagged_existing[0]
        raise KeychainError(
            "The signing identity was imported, but its Keychain name could not be determined.",
            hint="Inspect 'security find-identity -v -p codesigning' to pick the identity manually",
        )

    def identity_certificate_der(self, identity_name: str) -> bytes | None:
        """DER of the certificate behind a Keychain identity, or None."""
        args = ["find-certificate", "-c", identity_name, "-p"]
        if self.keychain is not None:
            args.extend(["-k", self.keychain])
        result = self._run(args)
        if result.returncode != 0:
            return None
        try:
            certificate = x509.load_pem_x509_certificate(result.stdout)
        except ValueError:
            return None
        return certificate.public_bytes(serialization.Encoding.DER)

    def find_identity(self, team_identifier: str) -> SigningIdentity | None:
        """Locate a previously imported development identity for the
        given team by listing identities with "security find-identity -v -p
        codesigning" and matching the team id suffix.
        """
        for name in sorted(self._identity_names()):
            # A Developer ID or distribution certificate is never valid
            # for a development provisioning profile.
            if not name.startswith(
                ("Apple Development:", "iPhone Developer:", "iOS Development:")
            ):
                continue
            match = _IDENTITY_TEAM_SUFFIX.search(name)
            if match is not None and match.group(1) == team_identifier:
                return SigningIdentity(
                    team_identifier=team_identifier,
                    keychain_identity=name,
                )
            # Apple's certificate name often carries a certificate id in
            # parentheses, not the team id. The subject OU is the team.
            if self._certificate_team(name) == team_identifier:
                return SigningIdentity(
                    team_identifier=team_identifier,
                    keychain_identity=name,
                )
        return None

    def _certificate_team(self, identity_name: str) -> str | None:
        """Team identifier from the certificate's subject OU, if readable."""
        args = ["find-certificate", "-c", identity_name, "-p"]
        if self.keychain is not None:
            args.extend(["-k", self.keychain])
        result = self._run(args)
        if result.returncode != 0:
            return None
        try:
            certificate = x509.load_pem_x509_certificate(result.stdout)
        except ValueError:
            return None
        for attribute in certificate.subject.get_attributes_for_oid(
            NameOID.ORGANIZATIONAL_UNIT_NAME
        ):
            return str(attribute.value)
        return None

    def delete_identity(self, identity_name: str) -> None:
        """Remove a previously imported identity. Best effort; missing
        identities are not an error.
        """
        args = ["delete-certificate", "-c", identity_name]
        if self.keychain is not None:
            args.append(self.keychain)
        result = self._run(args)
        if result.returncode == EXIT_ITEM_NOT_FOUND:
            return
        if result.returncode != 0:
            raise KeychainError(
                f"Could not delete the signing identity from the Keychain: {_stderr_text(result)}"
            )

    # ------------------------------------------------------------ helpers

    def _run(self, args: list[str]) -> subprocess.CompletedProcess[bytes]:
        return self._runner(args)

    def _run_interactive(
        self, command: list[str]
    ) -> subprocess.CompletedProcess[bytes]:
        """Run one security command through stdin.

        Secrets such as the session token and the p12 passphrase stay out
        of the process argument vector, where any same-user process could
        read them with ps.
        """
        line = " ".join(_quote_interactive(part) for part in command)
        return self._stdin_runner(line)

    def _identity_names(self) -> set[str]:
        """Parse the identity names from "security find-identity -v"."""
        args = ["find-identity", "-v", "-p", "codesigning"]
        if self.keychain is not None:
            args.append(self.keychain)
        result = self._run(args)
        if result.returncode != 0:
            raise KeychainError(
                f"Could not list the Keychain signing identities: {_stderr_text(result)}"
            )
        names: set[str] = set()
        for line in result.stdout.decode("utf-8", errors="replace").splitlines():
            match = _IDENTITY_LINE.match(line)
            if match is not None:
                names.add(match.group("name"))
        return names


def _blob_str(data: dict[str, object], key: str) -> str:
    """Read one required string field from a stored session blob."""
    value = data.get(key)
    if not isinstance(value, str) or value == "":
        raise KeychainError(
            f"The stored sideload session is missing the '{key}' field.",
            hint="Run: sideload auth logout, then sideload auth login",
        )
    return value


def _account_from_blob(
    email: str,
    dsid: str,
    account_data: dict[str, object],
    account_email: object,
) -> Account:
    """Rebuild the Account fields from the stored blob."""
    first_name = account_data.get("first_name")
    last_name = account_data.get("last_name")
    account_dsid = account_data.get("dsid")
    return Account(
        first_name=first_name if isinstance(first_name, str) else "",
        last_name=last_name if isinstance(last_name, str) else "",
        email=account_email if isinstance(account_email, str) else email,
        dsid=account_dsid if isinstance(account_dsid, str) else dsid,
    )
