# sideload

An open source macOS CLI that signs unsigned iOS .ipa files with an
Apple developer identity (free Apple ID personal team or paid team)
and installs them on a connected iPhone over USB.

    sideload auth login
    sideload install nightly.ipa

What it does:

- lists USB devices, installed apps, and uninstalls apps (with an
  explicit confirmation flag only)
- signs an .ipa end to end: team selection, device registration,
  certificate request, App ID, provisioning profile, entitlement
  rewriting, nested re-signing, repack
- installs the signed .ipa over usbmux through installation_proxy
- caches certificates, App IDs, and profiles per account and device
- stores the Apple ID session in the macOS Keychain; the Apple ID
  password is never stored anywhere

## Status

Implemented. Unit and integration tests cover the Apple protocol,
the signing pipeline, the device transport, and the CLI. A live end
to end install on a real device is the remaining acceptance step; see
ACCEPTANCE.md for the exact command contract.

## Security model

- The Apple ID password is read with getpass, used for one SRP
  exchange, and never written to disk, argv, or logs.
- The session token is stored in the Keychain as base64 JSON and
  written through `security -i` on stdin, so no secret appears in a
  process argument list.
- The signing .p12 is created in the per-user temp directory with 0600,
  imported with codesign-only trust, and deleted in a finally block.
- IPA extraction treats the archive as hostile: path and symlink
  escapes are rejected, size and entry counts are bounded, setuid bits
  are stripped, and the work directory is removed on exit.
- Apple requests refuse redirects, and TLS verification is never
  disabled.
- TLS verification uses the macOS system trust store, because certifi
  no longer carries Apple's current root. That store also honors roots
  you installed, such as mkcert or mitmproxy, so do not run a login
  while a TLS interception proxy is active.
- The Keychain gates other users and prompts other apps, but a process
  running as the same user can invoke /usr/bin/security and
  /usr/bin/codesign without an extra prompt. This is the same model
  Sideloadly and ipatool use.
- `uninstall` requires --yes; nothing is deleted without it.

## Prerequisites

- macOS with Xcode (uses codesign, security, and AOSKit)
- Python 3.12 or newer
- brew install libimobiledevice ideviceinstaller

## Install

    python3 -m venv .venv
    source .venv/bin/activate
    pip install -e .

## Commands

    sideload auth login|status|logout   Apple ID session (Keychain)
    sideload devices [--udid UDID]      list USB devices
    sideload apps [--udid UDID]          list installed apps
    sideload sign IPA [options]         sign without installing
    sideload install IPA [options]      sign and install
    sideload uninstall BID --yes        uninstall (explicit confirm)
    sideload doctor [--follow-logs]     diagnostics and log tailing

sign and install also accept tweak injection flags, repeatable:

    sideload install nightly.ipa --inject tweak.dylib
    sideload install nightly.ipa --inject-deb tweak.deb

Each `--inject` dylib is copied into the app bundle's Frameworks
directory and linked at launch through an LC_LOAD_DYLIB load command on
the main executable. Each `--inject-deb` unpacks the Debian package in
memory and injects every Library/MobileSubstrate/DynamicLibraries
*.dylib it contains, after a basic bundle id check against the tweak's
filter plist. Nothing is installed on the device and no package is
unpacked except the dylibs. Dylibs must contain an arm64 slice; fat
binaries are re-linked slice by slice.

Run `sideload <command> --help` for the full flag surface.

## License

MIT. See LICENSE. The tool can invoke ldid (AGPL), the optional
fallback signer, and libimobiledevice/ideviceinstaller (LGPL/GPL),
strictly as separate processes; no copyleft code is linked or vendored. See DESIGN.md for
the dependency study.
