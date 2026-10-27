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
- also signs from an existing developer certificate and provisioning
  profile (`--p12` and `--profile`), the certificate signing path
  Sideloadly offers: no Apple ID login and no Apple API call
- installs the signed .ipa over usbmux through installation_proxy
- caches certificates, App IDs, and profiles per account and device
- records the source IPA of every install and can re-sign and reinstall
  apps before the 7 day free profile expires
- optional per user launchd agent that refreshes every recorded device
  once a day, unattended
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
- The refresh daemon stores no credentials; it reuses the Keychain
  session, and its log never receives tokens or passwords.
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
    sideload refresh [--udid UDID] [--all]   re-sign recorded apps
    sideload daemon install|uninstall|status  daily refresh agent
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

## Auto refresh

Free provisioning profiles expire 7 days after issuance. Every install
records the absolute path of the source IPA, so `sideload refresh` can
re-sign each recorded app (reusing the cached certificate, App ID, and
profile, and downloading a fresh profile only when needed) and
reinstall it over USB before the old profile dies:

    sideload refresh [--udid UDID] [--all]

Refresh never prompts: no password, no 2FA code, no Trust dialog. It
needs a valid Keychain session, skips devices that are off, unpaired,
or have Developer Mode off, and reports and keeps records whose source
IPA is missing. It prints one line per app plus a summary. Exit 0
means every attempted app was refreshed, 1 means a failure or that
nothing could be refreshed, and 3 means the session expired and
`sideload auth login` is needed.

For Sideloadly style unattended refreshes, install the per user launchd
agent:

    sideload daemon install

It writes ~/Library/LaunchAgents/dev.sideload.refresh.plist (0600 file;
0700 directory when created) that runs the same interpreter with
`-m sideload refresh --all` once a day (RunAtLoad false), and pipes
stdout and stderr into
~/Library/Application Support/sideload/logs/refresh.log.

The agent cannot prompt for anything. It depends on a valid session
token in the Keychain; when the token expires the refresh exits 3 and
the log says to run `sideload auth login` in a terminal. The log
contains bundle ids, file paths, dates, and error messages only, never
tokens or passwords. Remove the agent with `sideload daemon uninstall`;
`sideload daemon status` reports whether the plist exists and whether
launchd lists the agent.

## App customization

`sign` and `install` accept Sideloadly-style tweaks. All of them are
optional; with none given the pipeline behaves exactly as before and
the Apple ID flow never changes.

    sideload sign app.ipa --name "Nightly Beta" --min-os 13.0
    sideload sign app.ipa --remove-plugins
    sideload install app.ipa --entitlements extra.plist --icon icon.png
    sideload sign app.ipa --supported-devices iPhone12,3 iPad13,2

- `--name TEXT` sets CFBundleDisplayName and CFBundleName.
- `--remove-plugins` deletes PlugIns/*.appex and any Watch content
  before any App ID, profile, or entitlement is requested, and the
  bundle inventory is recomputed right after, so removed extensions are
  never provisioned, never signed, and absent from the output IPA.
  This also saves App ID quota on free accounts (one App ID per
  extension).
- `--entitlements PATH` loads a plist and merges it into the
  entitlement set built for every bundle (main app and extensions, each
  against its own profile). Keys the profile does not grant are dropped
  with a warning; with --strict-entitlements they fail the run instead.
  Keys the resign pipeline manages itself (application-identifier,
  get-task-allow, com.apple.developer.team-identifier,
  keychain-access-groups) are always rewritten from the profile,
  whatever the plist says.
- `--min-os VERSION` sets MinimumOSVersion, and DeploymentTarget too
  when the Info.plist already carries that key.
- `--supported-devices LIST` replaces UISupportedDevices; pass one
  device identifier per argument.
- `--icon PATH.png` replaces the app icon with the macOS sips tool. It
  regenerates every PNG referenced by CFBundleIcons /
  CFBundleIconFiles / CFBundleIconFile, at the pixel size the file
  name encodes (AppIcon60x60@2x becomes a 120 pixel square) or the
  size of the existing file, including the @2x and @3x variants. Best
  effort and limited: icons inside compiled asset catalogs
  (Assets.car) cannot be edited by sips, and an app with no
  recognizable icon reference fails with a clear error instead of
  corrupting Info.plist.

Bad flag values (a missing file, a malformed version) exit 2 before
any Apple request; failures while editing the app exit 1.

## Certificate signing

Use a developer certificate and provisioning profile you already own,
with no Apple ID login and no Apple developer API call:

    sideload sign nightly.ipa --p12 dev.p12 --profile prof.mobileprovision
    sideload install nightly.ipa --p12 dev.p12 --profile prof.mobileprovision

The .p12 passphrase is read with getpass, never from argv, never
stored, and never printed. The identity is imported into the login
Keychain trusted for /usr/bin/codesign only. The profile decides the
team, the bundle id, and the devices: the app is re-signed as the
profile's bundle id unless the profile is a wildcard (TEAMID.*), which
keeps the original id. A wildcard profile also covers app extensions;
a specific profile cannot, and the run explains that before signing.
Modern .p12 files that the macOS security CLI refuses (OpenSSL 3 AES
exports) are re-wrapped locally and imported.

## License

MIT. See LICENSE. The tool can invoke ldid (AGPL), the optional
fallback signer, and libimobiledevice/ideviceinstaller (LGPL/GPL),
strictly as separate processes; no copyleft code is linked or vendored. See DESIGN.md for
the dependency study.
