"""Anisette data production on macOS.

Anisette data is a set of one time headers (machine identifier, OTP,
routing info, device description) that Apple's authentication endpoints
require to prove the request comes from a provisioned Apple device. It
is required by both the Grand Slam login and every developerservices2
request (verified in AltSign ALTAppleAPI.m sendRequestWithURL).

Legitimate sourcing on macOS, exactly as AltServer does
(AltServer/Anisette Data/AnisetteDataManager.swift) and as SideStore's
omnisette does (omnisette/src/aos_kit.rs): load the private frameworks
AOSKit and AuthKit, then call:

    AOSUtilities.retrieveOTPHeadersForDSID("-2")
        -> {"X-Apple-MD": otp, "X-Apple-MD-M": machine_id}
    AOSUtilities.machineSerialNumber -> X-Apple-I-SRL-NO
    AKDevice.currentDevice.uniqueDeviceIdentifier -> X-Mme-Device-Id
    AKDevice.currentDevice.localUserUUID         -> X-Apple-I-MD-LU
    AKDevice.currentDevice.serverFriendlyDescription -> X-MMe-Client-Info

"-2" selects the production provisioning environment. The routing
information constant is 84215040 (AltServer). When serial or build data
is unavailable, AltServer substitutes known valid fallbacks; this module
must document any substitution it performs.

Substitutions this module performs (all mirror AnisetteDataManager.swift):

    device_serial
        falls back to AltServer's valid fallback serial "C02LKHBBFD57"
        when AOSUtilities reports none.
    device_description
        keeps the model and OS groups of
        AKDevice.serverFriendlyDescription and drops the third client
        application group. Apple's GSA edge answers HTTP 503 to the old
        Xcode tag on current macOS, verified against the live endpoint.
        When the OS reports no description, CLIENT_INFO_TEMPLATE supplies
        AltServer's fallback model and build, still two groups only.
    locale  falls back to NSLocale.currentLocale, then "en_US".
    timezone
        falls back to "GMT" when NSTimeZone reports no abbreviation.

No third party anisette server is used: the data comes from this Mac's
own OS frameworks, the same source iTunes and Xcode use.

Ownership: AUTH agent.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any

import objc  # type: ignore[import-untyped]  # pyobjc-core ships no stubs

from sideload.errors import AnisetteError
from sideload.models import AnisetteData

# Production provisioning environment selector for retrieveOTPHeadersForDSID.
PROVISIONING_ENVIRONMENT = "-2"

# Production routing info constant used by AltServer when the OTP
# headers do not include one.
ROUTING_INFO_PRODUCTION = 84215040

# The client info AltServer reports, mimicking Xcode.
CLIENT_INFO_TEMPLATE = "<{device_model}> <{os_name};{os_version};{build}>"

AOSKIT_PATH = "/System/Library/PrivateFrameworks/AOSKit.framework"
AUTHKIT_PATH = "/System/Library/PrivateFrameworks/AuthKit.framework"

# Known valid fallbacks, identical to AltServer AnisetteDataManager.swift.
FALLBACK_DEVICE_SERIAL = "C02LKHBBFD57"
FALLBACK_DEVICE_MODEL = "iMac21,1"
FALLBACK_OS_VERSION = "13.4"
FALLBACK_OS_BUILD = "22F66"
FALLBACK_LOCALE = "en_US"
FALLBACK_TIMEZONE = "GMT"

# Framework paths already loaded in this process, so repeated
# get_anisette calls do not reload the bundles.
_loaded_framework_paths: tuple[str, ...] | None = None


def _invoke(target: object, selector: str) -> Any:
    """Read an ObjC property or call a zero argument method by name.

    pyobjc exposes Objective-C properties and methods identically at
    the attribute level, so the callable check handles both.
    """
    value = getattr(target, selector)
    if callable(value):
        return value()
    return value


def _try_invoke(target: object, selector: str) -> Any:
    """Invoke a property; None when the value is genuinely unavailable.

    The Objective-C runtime raises a variety of exception types for
    missing selectors and unavailable values, so every failure maps to
    None and the documented fallback applies.
    """
    try:
        return _invoke(target, selector)
    except Exception:  # noqa: BLE001, any ObjC failure means "unavailable"
        return None


def _client_time() -> str:
    """ISO 8601 UTC timestamp, matching AltSign's NSISO8601DateFormatter."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class AnisetteProvider:
    """Produces fresh AnisetteData using macOS private frameworks."""

    def get_anisette(self) -> AnisetteData:
        """Return a fresh anisette header set.

        Each call must retrieve a fresh OTP (the one time password is
        short lived). Raises AnisetteError when the frameworks are
        missing (non Apple hardware, stripped macOS), when loading is
        blocked, or when the AOSUtilities response lacks required keys.
        """
        self._load_frameworks()
        otp_headers = self._otp_headers()
        serial = self._machine_serial()
        device = self._current_device()
        return AnisetteData(
            machine_id=otp_headers["X-Apple-MD-M"],
            one_time_password=otp_headers["X-Apple-MD"],
            local_user_id=self._device_string(device, "localUserUUID"),
            routing_info=ROUTING_INFO_PRODUCTION,
            device_unique_id=self._device_string(device, "uniqueDeviceIdentifier"),
            device_serial=serial,
            device_description=self._device_description(device),
            locale=self._locale(device),
            timezone=self._timezone(),
            client_time=_client_time(),
        )

    # ------------------------------------------------------------ loading

    def _load_frameworks(self) -> None:
        """Load AOSKit and AuthKit, or raise AnisetteError."""
        global _loaded_framework_paths
        paths = (AOSKIT_PATH, AUTHKIT_PATH)
        if _loaded_framework_paths == paths:
            return
        for path in paths:
            if not os.path.isdir(path):
                raise AnisetteError(
                    f"The Apple framework at {path} is not available on this Mac.",
                    hint=(
                        "anisette data requires macOS with the original system "
                        "frameworks (AOSKit, AuthKit); sideload refuses to use "
                        "third party anisette servers"
                    ),
                )
        try:
            for name, path in (("AOSKit", paths[0]), ("AuthKit", paths[1])):
                objc.loadBundle(name, {}, bundle_path=path)
        except Exception as exc:  # pragma: no cover, depends on host state
            raise AnisetteError(
                f"Could not load the Apple frameworks at {paths[0]} or {paths[1]}: {exc}",
                hint="check that System Integrity Protection is enabled and macOS is unmodified",
            ) from exc
        _loaded_framework_paths = paths

    def _lookup_class(self, name: str) -> Any:
        try:
            return objc.lookUpClass(name)
        except Exception as exc:
            raise AnisetteError(
                f"The class {name} is not available after loading the Apple frameworks.",
                hint="this Mac's AOSKit or AuthKit build is unusual; file a bug report",
            ) from exc

    def _optional_class(self, name: str) -> Any:
        """Look up a class that may legitimately be absent (Foundation)."""
        try:
            return objc.lookUpClass(name)
        except Exception:  # noqa: BLE001, absence means "use the fallback"
            return None

    # ------------------------------------------------------------ values

    def _otp_headers(self) -> dict[str, str]:
        """One time password headers from AOSUtilities for production."""
        utilities = self._lookup_class("AOSUtilities")
        try:
            raw = utilities.retrieveOTPHeadersForDSID_(PROVISIONING_ENVIRONMENT)
        except Exception as exc:
            raise AnisetteError(
                f"AOSUtilities could not produce OTP headers: {exc}",
                hint="sign in to an Apple ID once in System Settings so this Mac is provisioned",
            ) from exc
        if raw is None:
            raise AnisetteError(
                "AOSUtilities returned no one time password headers.",
                hint="this Mac is not provisioned for Apple services yet; sign in with an Apple ID once",
            )
        headers = {str(key): str(value) for key, value in dict(raw).items()}
        for key in ("X-Apple-MD", "X-Apple-MD-M"):
            if not headers.get(key):
                raise AnisetteError(f"The AOSUtilities OTP response lacks the {key} value.")
        return headers

    def _machine_serial(self) -> str:
        """Hardware serial, with AltServer's documented fallback."""
        utilities = self._lookup_class("AOSUtilities")
        serial = _try_invoke(utilities, "machineSerialNumber")
        if serial is None or str(serial) == "":
            # Substitution documented in the module docstring.
            return FALLBACK_DEVICE_SERIAL
        return str(serial)

    def _current_device(self) -> Any:
        device_class = self._lookup_class("AKDevice")
        try:
            device = _invoke(device_class, "currentDevice")
        except Exception as exc:
            raise AnisetteError(f"AKDevice has no current device: {exc}") from exc
        if device is None:
            raise AnisetteError(
                "AKDevice reported no current device.",
                hint="run once while signed in to an Apple ID on this Mac",
            )
        return device

    def _device_string(self, device: Any, selector: str) -> str:
        try:
            value = _invoke(device, selector)
        except Exception as exc:
            raise AnisetteError(f"AKDevice did not provide {selector}: {exc}") from exc
        if value is None or str(value) == "":
            raise AnisetteError(f"AKDevice did not provide {selector}.")
        return str(value)

    def _device_description(self, device: Any) -> str:
        """Model and OS client info from the live OS description.

        Only the first two groups are sent. Apple's GSA edge answers
        HTTP 503 when the third client application group is present on
        current macOS, so the old Xcode tag AltServer used is dropped.
        """
        description = _try_invoke(device, "serverFriendlyDescription")
        text = str(description) if description is not None else ""
        groups = text.split()
        if (
            len(groups) >= 2
            and groups[0].startswith("<")
            and groups[1].startswith("<")
        ):
            return f"{groups[0]} {groups[1]}"
        return CLIENT_INFO_TEMPLATE.format(
            device_model=FALLBACK_DEVICE_MODEL,
            os_name="macOS",
            os_version=FALLBACK_OS_VERSION,
            build=FALLBACK_OS_BUILD,
        )

    def _locale(self, device: Any) -> str:
        device_locale = _try_invoke(device, "locale")
        if device_locale is not None:
            identifier = _try_invoke(device_locale, "localeIdentifier")
            if identifier is not None:
                return str(identifier)
        locale_class = self._optional_class("NSLocale")
        if locale_class is not None:
            current = _try_invoke(locale_class, "currentLocale")
            if current is not None:
                identifier = _try_invoke(current, "localeIdentifier")
                if identifier is not None:
                    return str(identifier)
        return FALLBACK_LOCALE

    def _timezone(self) -> str:
        zone_class = self._optional_class("NSTimeZone")
        if zone_class is not None:
            zone = _try_invoke(zone_class, "localTimeZone")
            if zone is not None:
                abbreviation = _try_invoke(zone, "abbreviation")
                if abbreviation is not None:
                    return str(abbreviation)
        return FALLBACK_TIMEZONE
