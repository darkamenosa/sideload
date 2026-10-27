"""Error taxonomy for sideload.

Every failure the CLI can report maps to exactly one exception class in
this module. The taxonomy is derived from failure modes verified in
AltSign (ALTAppleAPI error domains), SideStore's icloud-auth, and the
installation_proxy error names surfaced by libimobiledevice's
installation_proxy.c. See DESIGN.md "Error taxonomy" for the raw error
to exception mapping.

Ownership: shared (GLUE agent). The auth, sign, and device agents must
raise exceptions from this module; they must not invent parallel
hierarchies. Adding a new class requires editing only this file.
"""

from __future__ import annotations

# Process exit codes returned by sideload.cli.main().
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_REAUTH = 3

# installation_proxy "Error" name strings that sideload knows how to
# translate into a human hint. Sourced from libimobiledevice
# src/installation_proxy.c (instproxy_strtoerr) and Apple TN2319.
INSTALL_ERROR_HINTS: dict[str, str] = {
    "ApplicationVerificationFailed": (
        "The device rejected the code signature. Common causes: the embedded "
        "mobileprovision does not match the signing certificate, the profile "
        "expired, the device UDID is not in the profile, or the binary requests "
        "entitlements the profile does not grant. Run: sideload doctor"
    ),
    "BundleVerificationFailed": (
        "The bundle failed verification. Common causes: broken Info.plist, "
        "missing executable, or resources modified after the outer signature "
        "was applied (stale CodeResources)"
    ),
    "MismatchedApplicationIdentifierEntitlement": (
        "The application-identifier entitlement does not match the profile. "
        "The app was previously installed with a different team or bundle id. "
        "Uninstall it first: sideload uninstall <bundle-id> --yes"
    ),
    "PackageExtractionFailed": "The IPA archive could not be extracted on device",
    "InsufficientDiskSpace": "The device has no free space for the app",
    "EmbeddedProfileInstallFailed": (
        "The embedded.mobileprovision was rejected. It may be expired or "
        "issued for a different device"
    ),
    "NotEntitled": "The account or profile is not entitled to perform this install",
    "InstallProhibited": "Install blocked on device (screen time, MDM, or supervised restriction)",
    "APIInternalError": "Installation proxy internal error, retry",
    "UnknownError": "Installation proxy returned an unknown error, retry",
}


class SideloadError(Exception):
    """Base class for all sideload failures.

    Attributes:
        hint: optional actionable advice shown to the user after the
            error message, on its own line prefixed with "hint:".
    """

    def __init__(self, message: str, *, hint: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint

    @property
    def exit_code(self) -> int:
        """Process exit code to use for this error."""
        return EXIT_ERROR


class UsageError(SideloadError):
    """Invalid CLI arguments or missing required options."""

    @property
    def exit_code(self) -> int:
        return EXIT_USAGE


# ---------------------------------------------------------------- auth

class AuthError(SideloadError):
    """Apple ID authentication failed."""


class TwoFactorError(AuthError):
    """A 2FA security code was required and the attempt failed."""


class SessionExpiredError(AuthError):
    """The stored Grand Slam session token expired or was rejected.

    The CLI catches this, prints a notice, and asks the user to run
    "sideload auth login" again. The Apple ID password is never stored.
    """

    @property
    def exit_code(self) -> int:
        return EXIT_REAUTH


class AnisetteError(AuthError):
    """Anisette data could not be produced on this Mac."""


# ------------------------------------------------------- developer API

class DeveloperAPIError(SideloadError):
    """developerservices2.apple.com returned a non-zero resultCode.

    Attributes:
        result_code: the numeric resultCode from the action response.
        user_string: the human string from the response, when present.
    """

    def __init__(
        self,
        message: str,
        *,
        result_code: int | None = None,
        user_string: str | None = None,
        hint: str | None = None,
    ) -> None:
        super().__init__(message, hint=hint)
        self.result_code = result_code
        self.user_string = user_string


class AppIDQuotaExceededError(DeveloperAPIError):
    """ resultCode 9120: the free account hit its App ID creation limit.

    Free accounts can register 10 App IDs and they expire after 7 days
    (developer.apple.com/help/account/basics/about-your-developer-account).
    """


class BundleIdentifierUnavailableError(DeveloperAPIError):
    """resultCode 9401/9412: the bundle identifier is taken or invalid."""


class InvalidCertificateRequestError(DeveloperAPIError):
    """resultCode 3250: Apple rejected the submitted CSR."""


class DeviceAlreadyRegisteredError(DeveloperAPIError):
    """resultCode 35 with "already exists": device UDID already in team."""


class AccountLimitError(SideloadError):
    """A free account limit hit at install time, not at API time.

    For example the 3 active apps per device limit; the device rejects
    the install rather than the Apple API.
    """


# -------------------------------------------------------------- signing

class SigningError(SideloadError):
    """codesign or ldid failed to sign a binary."""


class KeychainError(SideloadError):
    """The macOS keychain could not be created, read, or written."""


class EntitlementsError(SideloadError):
    """Entitlements could not be applied.

    Attributes:
        dropped: entitlement keys requested by the app but not granted
            by the provisioning profile. The tool drops them with a
            warning unless --strict-entitlements is set.
    """

    def __init__(
        self,
        message: str,
        *,
        dropped: list[str] | None = None,
        hint: str | None = None,
    ) -> None:
        super().__init__(message, hint=hint)
        self.dropped = dropped or []


class ProfileError(SideloadError):
    """The provisioning profile is unusable for this app or device."""


class ProfileExpiredError(ProfileError):
    """The profile expiration date has passed (7 days for free accounts)."""


class DeviceNotProvisionedError(ProfileError):
    """The device UDID is missing from the profile ProvisionedDevices."""


class BundleIDMismatchError(ProfileError):
    """The app bundle id does not match the profile application-identifier."""


# ------------------------------------------------------------------ IPA

class IPAError(SideloadError):
    """The input file is not a workable IPA."""


class NotAnIPAError(IPAError):
    """The archive has no Payload directory."""


class NoAppBundleError(IPAError):
    """The Payload directory contains no .app bundle."""


class UnsupportedIPAError(IPAError):
    """The IPA needs features sideload cannot provide.

    For example a FairPlay encrypted App Store binary (no decryptable
    code pages) or a watchOS pair requiring a separate watch profile.
    """


# ---------------------------------------------------------------- device

class DeviceError(SideloadError):
    """A device level failure: usbmux, lockdown, or pairing."""


class NoDeviceFoundError(DeviceError):
    """No USB device matched the given UDID."""


class PairingError(DeviceError):
    """The device is not paired or the pairing record is invalid.

    Hint: run "idevicepair pair" or "sideload devices --pair" and accept
    the trust dialog on the iPhone.
    """


class DeveloperModeDisabledError(DeviceError):
    """iOS 16 or later requires Developer Mode for developer signed apps."""


class TransportError(DeviceError):
    """An external tool is missing: idevice_id, ideviceinfo, or ideviceinstaller.

    Install with: brew install libimobiledevice ideviceinstaller
    """


class InstallError(SideloadError):
    """installation_proxy reported an error while installing or removing.

    Attributes:
        install_error_name: the "Error" string from the proxy status
            plist, for example "ApplicationVerificationFailed".
        error_description: the "ErrorDescription" string, when present.
    """

    def __init__(
        self,
        message: str,
        *,
        install_error_name: str | None = None,
        error_description: str | None = None,
        hint: str | None = None,
    ) -> None:
        super().__init__(message, hint=hint)
        self.install_error_name = install_error_name
        self.error_description = error_description


class UninstallConfirmationRequired(SideloadError):
    """Uninstall was attempted without the explicit --yes flag.

    Uninstalling removes app data; the CLI refuses to run it without
    confirmation and never prompts interactively on its own.
    """
