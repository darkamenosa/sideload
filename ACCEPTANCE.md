# Acceptance criteria

The finished CLI must support exactly these commands with exactly
these observable behaviors. Flags are frozen in src/sideload/cli.py
build_parser(). Exit codes: 0 success, 1 failure, 2 usage error,
3 session expired (re-login needed).

## Preconditions

- macOS with Xcode installed (codesign, security).
- brew install libimobiledevice ideviceinstaller
- The iPhone is paired (Trust dialog accepted) and Developer Mode is
  on (Settings, Privacy and Security, Developer Mode; a one time
  device action that cannot be automated).

## Commands

### sideload auth login [--email EMAIL] [--rotate-certificate]

- Prompts for email when omitted, then for the password (input not
  echoed), then for a six digit 2FA code when Apple requires one.
- On success prints the account name, the DSID, and each team with
  its type (free or paid), and stores the session in the Keychain.
- The password is never stored: `sideload auth logout` plus a fresh
  login is the recovery path, and the session expiry is printed.
- Wrong credentials exit 1 with the GSA error surfaced; a wrong 2FA
  code asks again (up to 3 attempts) then exits 1.

### sideload auth status

- Prints the stored Apple ID email, DSID, token expiry date and time,
  selected team, and a tool check table (found or missing, with install
  hints).
- Missing session exits 3 with "run: sideload auth login".

### sideload auth logout

- Deletes the Keychain session. Cached profiles and App ID mirrors are
  kept. Exits 0 even when nothing was stored.

### sideload devices [--udid UDID] [--pair]

- Lists every USB device visible to usbmuxd: UDID, device name,
  product type, iOS version, paired yes or no, developer mode on,
  off, or unknown.
- With --pair: runs the pairing flow, prints "tap Trust on the
  device", and waits; on success the pairing state prints yes.
- No devices: exit 1 with a hint to plug the device in over USB.

### sideload apps [--udid UDID] [--all]

- Lists installed apps, one per line: bundle id, display name,
  version. Default lists user apps only; --all includes system apps.
- Unpaired device: exit 1 with the pairing hint.

### sideload sign IPA [--output OUT] [--bundle-id ID] [--team TEAMID] [--strict-entitlements] [--p12 PATH] [--profile PATH]

- Signs the IPA without touching a device. Prints, in order:
  the selected team, certificate created or reused, device
  registration skipped or done, App ID created or reused (with the
  resigned bundle id), profile expiry date and time, entitlement keys
  dropped with a warning line per key, and the output path.
- Default output: the original file name plus ".signed.ipa".
- With --strict-entitlements any dropped key is an error instead.
- App ID quota exhaustion (free accounts) exits 1 with the 10 App IDs
  explanation and which old App IDs expire soon.

### sideload install IPA [--udid UDID] [--bundle-id ID] [--team TEAMID] [--strict-entitlements] [--p12 PATH] [--profile PATH]

- Performs the sign flow, then installs over USB.
- Prints installation stages (CreatingStagingDirectory,
  ExtractingPackage, VerifyingApplication) with a percentage, then
  success and the resigned bundle id.
- Developer Mode off: exit 1 with the exact Settings path.
- Device signature rejection: exit 1 with the installation_proxy error
  name, description, and the matching hint, plus the suggestion
  "run: sideload doctor --follow-logs" for the underlying amfid or
  installd reason.

### Certificate signing: sign and install with --p12 and --profile

- Both flags together switch sign and install to the certificate
  pipeline: no Apple ID session is loaded, no anisette is produced, and
  no developer API call happens. Passing only one of the two flags is
  a usage error (exit 2). The command works with no stored session at
  all, and install on this path never exits 3.
- The .p12 passphrase is read with getpass (never argv, never stored,
  never logged); a wrong passphrase exits 1 with a clean message before
  anything touches the Keychain.
- The .mobileprovision is decoded with the real `security cms` path
  and validated: expiry always, the targeted device on install (sign
  only skips the device check), and the bundle id.
- The profile application-identifier decides the bundle id that is
  signed; a conflicting `--bundle-id` exits 2, and `--team` must match
  the profile team. The .p12 certificate must be one of the profile's
  DeveloperCertificates, else exit 1 before signing.
- Info.plist is rewritten to the profile bundle id and the profile is
  embedded before signing. A wildcard profile (TEAMID.*) keeps the
  original bundle id and honors `--bundle-id`; extensions get child ids
  under it. A specific profile cannot cover app extensions and the run
  fails before signing with that explanation.
- The identity is imported into the login Keychain trusted for
  /usr/bin/codesign only. Modern .p12 files the macOS security CLI
  refuses on format grounds are re-wrapped locally and imported.
- install with the flags runs the regular device install afterwards
  (stages, hints, and the install record keyed by the profile team).

### sideload uninstall BUNDLE_ID [--udid UDID] --yes

- Without --yes: prints that the flag is required and exits 2. Never
  prompts.
- With --yes: uninstalls and removes the app data, prints the removed
  bundle id, exit 0.

### sideload doctor [--udid UDID] [--follow-logs]

- Prints a health report: each required tool found or missing,
  pairing state, developer mode state, device free disk space, and the
  count of apps this tool installed on the device (from the cache).
- With --follow-logs: after the report, streams idevicesyslog lines
  filtered to installd, amfid, and AppleMobileFileIntegrity until
  interrupted with Ctrl-C.

## Acceptance scenario

With the paired iPhone 12 on iOS 17.6.1 connected over USB:

    sideload auth login
    sideload install nightly.ipa
    sideload apps

Expected: install prints the resign summary, the install stages, and
exits 0; the app appears in the apps listing under its resigned bundle
id; the app launches on the device provided its entitlements fit the
free profile (a tool that demands private entitlements will install
and then be killed at launch, which the sign step warns about).
