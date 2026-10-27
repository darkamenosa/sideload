# sideload design

`sideload` is an open source macOS CLI that signs an unsigned iOS .ipa
with an Apple developer identity (free Apple ID personal team or paid
team) and installs it on a connected iPhone over USB. It also lists
devices, lists installed apps, uninstalls apps, and caches developer
resources per account and device.

Sideloadly is closed source and this project does not copy or reverse
it. Everything below was verified by reading the code and docs of the
open source projects listed in the final section.

## 1. Acceptance scenario

Re-sign a nightly .ipa of a jailbreak adjacent tool and install it on
an iPhone 12 (UDID 00008101-000000000000000E) running iOS 17.6.1 from a
Mac running macOS 26 with Xcode 27 installed:

    sideload auth login
    sideload install nightly.ipa

The tool must register the device with the team, create the App ID,
request the certificate, download the profile, rewrite entitlements,
re-sign nested binaries, and install over usbmux. Because the target
is a stock iOS 17.6.1 device, the app only launches if the nightly's
entitlements fit what a free profile grants (section 7). That
constraint is inherent to Apple's code signing and is documented, not
hidden.

## 2. Architecture

Three isolated subsystems plus shared plumbing. Each subsystem is
implemented by one agent and communicates with the others only through
the pinned interfaces in this repository (models, errors, function
signatures).

    CLI (cli.py)
      |
      +-- AUTH:  keychain.py, apple/anisette.py, apple/auth.py
      |           output: AppleSession (dsid, GS token, expiry)
      |
      +-- SIGN:  apple/developer.py, signing/{csr,profile,
      |           entitlements,ipa,signer}.py, cache.py reads/writes
      |           input:  AppleSession, AnisetteProvider
      |           output: signed .ipa, ProvisioningProfile
      |
      +-- DEVICE: device/{usbmux,installer}.py
      |           input:  signed .ipa, device UDID
      |           output: install result, structured errors
      |
      +-- shared: models.py, errors.py, config.py, cache.py

Data flow for `sideload install foo.ipa`:

1. Load the Apple ID session from the Keychain. If missing or expired,
   exit 3 and tell the user to run `sideload auth login`.
2. Auth side: produce one AnisetteData set from macOS AOSKit for every
   Apple request in this run.
3. List teams (listTeams.action), pick the free personal team (or the
   team named with `--team`).
4. Ensure the signing certificate exists: list certificates, else
   generate an RSA-2048 key locally, submit a CSR
   (ios/submitDevelopmentCSR.action), import the returned certificate
   plus private key into the login Keychain for codesign.
5. Register the device UDID with the team (ios/addDevice.action) if it
   is missing from ios/listDevices.action. A "35 already exists"
   response is treated as success.
6. Compute the resigned bundle id (original plus "." plus lowercased
   team id, AltStore rule). Reuse the cached App ID if it exists in
   ios/listAppIds.action, else create it (ios/addAppId.action). Each
   app extension gets a child App ID of the form
   `<parent_resigned>.<extension>`.
7. Download the provisioning profile
   (ios/downloadTeamProvisioningProfile.action) unless a cached one is
   still valid for the bundle id and device. Parse the CMS profile.
8. Unzip the IPA, inventory bundles (main app, PlugIns extensions,
   Frameworks, loose dylibs), rewrite Info.plist bundle ids, remove
   App Store artifacts, and write embedded.mobileprovision into every
   bundle root.
9. Build entitlements: profile Entitlements as the base, merge the
   app's own keys only where granted, drop the rest with a warning
   (fail with --strict-entitlements).
10. Sign deepest first (dylibs, framework binaries, extension bundles,
    main executable last) using codesign with the Keychain identity.
    LDIDSigner exists in signer.py but the CLI does not select it in v1.
11. Repack the IPA.
12. Device side: verify pairing and Developer Mode, then
    ideviceinstaller -u <udid> -i <signed.ipa>. Parse progress stages
    and any structured error, map it to the taxonomy, and print the
    hint. On signature failures offer `sideload doctor --follow-logs`.
13. Record the install in the cache (bundle ids, App ID, profile
    UUID, device, account) so refreshes reuse resources.
14. Launch: the flow ends at install. The user launches the app by
    tapping its icon on the Home Screen. Launching from the CLI would
    require mounting a Developer Disk Image and driving debugserver;
    that is explicitly out of scope for v1 (section 9).

## 3. Chosen stack and licenses

Project license: MIT (LICENSE file). The tool is designed so that no
copyleft code is linked or imported; all copyleft components run as
separate subprocesses, which does not create a derivative work.

| Component | Role | License | Why |
|---|---|---|---|
| Python 3.12 stdlib | argparse, plistlib, zipfile, subprocess | PSF | no dependency needed for CLI, plists, zip |
| requests | HTTP for GSA and developer services | Apache-2.0 | simple, ubiquitous; used by every prior art tool |
| cryptography | RSA keypair, CSR, CMS profile parsing fallback | Apache-2.0 / BSD dual | already on the host (46.0.5); AltSign uses OpenSSL for the same steps |
| pyobjc-core | load AOSKit/AuthKit private frameworks for anisette | MIT | same native anisette source AltServer uses on macOS; avoids any third party anisette server |
| codesign + security (macOS) | signing, keychain, CMS decode | Apple system tools | present on every Mac with Xcode; native CodeResources sealing |
| ldid 2.1.5 (subprocess) | signing fallback without keychain | AGPL-3.0-or-later (Homebrew) | proven by AltSign/SideStore for exactly this use; invoked as a separate process only |
| libimobiledevice 1.4.0 (subprocess) | idevice_id, ideviceinfo, idevicepair, ideviceprovision | LGPL-2.1 | already installed on the host; battle tested usbmux and lockdown |
| ideviceinstaller 1.2.0 (subprocess) | installation_proxy front end | GPL-2.0-or-later | not currently installed; requires `brew install ideviceinstaller`; subprocess only |
| pymobiledevice3 | NOT a dependency | GPL-3.0-or-later | studied as prior art; rejected as a library (viral GPL plus a very heavy dependency tree including fastapi and uvicorn); usable by users as an alternative CLI, but this project never imports or ships it |

Rejected alternatives, for the record:

- pyprovision (anisette): requires a D compiler at install time.
- Remote anisette servers (SideStore anisette servers): sends OTP
  material to third parties; unnecessary on macOS where AOSKit is the
  OS's own legitimate source.
- Implementing usbmux/lockdown/AFC in pure Python: roughly 2000 lines
  of protocol code including an AFC client and lockdown SSL details,
  far beyond the per module budget, and it would duplicate what
  libimobiledevice already does correctly.
- ipatool's SAP emulation approach (Go project running Apple's own
  binaries under a Unicorn emulator): store specific, heavy, and not
  needed for the developer services flow.

## 4. Apple developer API calls in order

All shapes below were read directly from AltSign
(AltSign/Apple API/ALTAppleAPI.m and ALTAppleAPI+Authentication.m) and
cross checked against SideStore's current Rust implementation
(SideStore/apple-private-apis, icloud-auth and omnisette crates).

### 4.1 Anisette

Every Apple request in sections 4.2 and 4.3 must carry fresh anisette
headers because the one time password is single use. On macOS the
legitimate source is the OS private framework AOSKit (used by AltServer
and SideStore's omnisette aos_kit.rs):

    load /System/Library/PrivateFrameworks/AOSKit.framework
    load /System/Library/PrivateFrameworks/AuthKit.framework
    AOSUtilities.retrieveOTPHeadersForDSID("-2")
        -> {"X-Apple-MD": <otp>, "X-Apple-MD-M": <machine id>}
    AOSUtilities.machineSerialNumber -> X-Apple-I-SRL-NO
    AKDevice.currentDevice.uniqueDeviceIdentifier -> X-Mme-Device-Id
    AKDevice.currentDevice.localUserUUID -> X-Apple-I-MD-LU
    AKDevice.currentDevice.serverFriendlyDescription -> X-MMe-Client-Info

Production routing info constant: 84215040. The client info mimics
Xcode, for example:

    <Mac15,12> <macOS;26.6.2;25G83>

Only the model and OS groups are sent. The third client application
group made Apple's GSA edge answer HTTP 503 (verified live), so it is
dropped.

If AOSKit is unavailable (stripped macOS, unusual SIP state) the tool
fails with AnisetteError; there is no workaround that does not involve
shipping provisioning data or a third party server, and this project
refuses both.

### 4.2 Grand Slam (GSA) login: SRP-6a

Endpoint for all steps: POST https://gsa.apple.com/grandslam/GsService2
with an XML plist body {"Header": {"Version": "1.0.1"}, "Request": {...}}
and headers Content-Type: text/x-xml-plist, X-MMe-Client-Info,
User-Agent "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0".

Steps:

1. o=init: Request carries u (Apple ID email), ps ["s2k", "s2k_fo"],
   A2k (client SRP ephemeral bytes), cpd (the client dict from
   apple/auth.py build_cpd). Response carries sp ("s2k" or "s2k_fo"),
   c, s (salt bytes), i (PBKDF2 iterations), B (server ephemeral).
   SRP is RFC 5054 2048 bit group with SHA-256 and the no-username-in-x
   variant. The password key is
   PBKDF2-HMAC-SHA256(SHA256(password), salt, i, 32 bytes), where the
   SHA-256 digest is hex encoded for "s2k_fo" and raw for "s2k".
2. o=complete: Request carries c and M1 (client proof). Response
   carries M2 (server proof), spd (encrypted login plist), sc, np.
   spd decrypts with AES-256-CBC, PKCS7, key
   HMAC-SHA256(session_key, "extra data key:"), IV
   HMAC-SHA256(session_key, "extra data iv:"), and contains adsid,
   GsIdmsToken, sk, c. Status error -22406 is wrong credentials.
3. If Status has au "trustedDeviceSecondaryAuth": push a code with GET
   https://gsa.apple.com/auth/verify/trusteddevice carrying
   X-Apple-Identity-Token base64("<adsid>:<GsIdmsToken>"), then
   validate with GET
   https://gsa.apple.com/grandslam/GsService2/validate adding the
   security-code header with the six digits from the user. Error
   -21669 is a wrong code. On success the whole SRP exchange repeats.
4. o=apptokens: Request carries u (adsid), app
   ["com.apple.gs.xcode.auth"], c, t (GsIdmsToken), cpd, and checksum
   HMAC-SHA256(session_key, "apptokens" + adsid + app). The nested
   "HMAC key:" derivation belongs only to the np check. Response
   carries et: AES-GCM blob
   ("XYZ" magic, 16 byte IV, ciphertext, 16 byte tag) decrypting with
   sk to a plist with t[com.apple.gs.xcode.auth] = {token, expiry}.

The result is AppleSession: dsid (adsid), gs token, and expiry. The
password is used in memory only and never persisted anywhere.

### 4.3 developerservices2 actions

Base URL https://developerservices2.apple.com/services/QH65B2/
(client id XABBG36SBA, protocol version QH65B2, User-Agent "Xcode",
X-Xcode-Version "11.2 (11B41)", X-Apple-App-Info
"com.apple.gs.xcode.auth", X-Apple-I-Identity-Id dsid, X-Apple-GS-Token
gs token, plus all anisette headers). Requests are POST with an XML
plist body: {"clientId", "protocolVersion", "requestId" (uppercase
UUID), "teamId" when team scoped, action params}. Responses are XML
plists; resultCode 0 means success, anything else is an error with
userString.

Call order for one install:

| # | Action | Body params | Response key | Notes |
|---|---|---|---|---|
| 1 | listTeams.action | none | teams | teamId, name, type; free when type Individual and the single membership name contains "free" |
| 2 | viewDeveloper.action | none | developer | account display |
| 3 | ios/listDevices.action | teamId | devices | name, deviceNumber |
| 4 | ios/addDevice.action | deviceNumber, name | device | register the iPhone; code 35 with "already exists" is success |
| 5 | services/v1/certificates (JSON) | filter[certificateType]=IOS_DEVELOPMENT | data | list existing certs; JSON:API with urlEncodedQueryParams body and X-HTTP-Method-Override |
| 6 | ios/submitDevelopmentCSR.action | csrContent (PEM), machineId (UUID), machineName | certRequest | RSA-2048 CSR; code 3250 invalid CSR; free teams should keep few certs and revoke previous ones |
| 7 | services/v1/certificates/<id> DELETE | none | empty | revoke, tunneled via method override |
| 8 | ios/listAppIds.action | teamId | appIds | appIdId, name, identifier |
| 9 | ios/addAppId.action | identifier, name | appId | code 9120 weekly App ID limit, 9401 taken, 9412 invalid |
| 10 | ios/downloadTeamProvisioningProfile.action | appIdId | provisioningProfile | provisioningProfileId, encodedProfile (CMS .mobileprovision bytes) |
| 11 | ios/deleteAppId.action, ios/deleteProvisioningProfile.action | appIdId, provisioningProfileId | resultCode | quota hygiene commands |

Profiles are CMS signed plists; decode with `security cms -D`. The
free profile contains: Name, UUID, TeamIdentifier, CreationDate,
ExpirationDate (7 days out), Entitlements (application-identifier
TEAMID.bundle, get-task-allow true, team-identifier),
ProvisionedDevices (UDIDs), DeveloperCertificates (DER), and
LocalProvision true.

### 4.4 Free account limits (Apple primary source)

From developer.apple.com/help/account/basics/about-your-developer-account:

- up to 10 App IDs at a time, each expiring after 7 days
- up to 3 registered devices per platform, each expiring after 7 days
- up to 3 active sideloaded apps per device
- provisioning profiles expire 7 days from issuance

Certificate validity for personal teams is not published by Apple;
empirically Xcode personal team certificates show roughly a one year
expiry and AltStore caches and reuses the certificate while the 7 day
profile drives the weekly refresh cycle. Because Apple allows only a
few concurrent development certificates, the tool revokes its previous
certificate before creating a new one when the user opts in with
`sideload auth login --rotate-certificate` (AltStore does the same).
Only certificates whose machine name matches this Mac are revoked, and
only after the input IPA has been validated, so a typo cannot destroy
another machine's identity or wipe the team's certificate list.

2FA is mandatory for Apple Account sign in; the code is read
interactively, never stored.

## 5. Credential storage design

- Apple ID password: never written to disk or Keychain. It exists in
  process memory for the PBKDF2 step of one login and is dropped.
- Session: a Keychain generic password, service
  "dev.sideload.session", account = Apple ID email, value = base64 of
  the JSON {dsid, gs_token, token_expiry, account fields}. Base64 has
  no quotes or apostrophes, so the value survives the security CLI's
  stdin parser unchanged. Writes go through `security -i` on stdin, so
  the token never appears in the process argument vector; reads and
  deletes use find-generic-password and delete-generic-password.
- Signing identity: private key generated locally (RSA-2048), CSR
  submitted, certificate packaged as a .p12 in the per-user temp
  directory (0600, never the state directory), imported into the login
  Keychain with `security import -T /usr/bin/codesign` so later codesign
  runs do not re-prompt, then deleted. The import command, including
  the p12 passphrase, travels on stdin, never argv. Identity discovered
  via `security find-identity -v -p codesigning` by team id suffix.
- Cached profiles are reused only while the profile's team, device
  list, and developer certificate still match the selected team, the
  target device, and the current Keychain identity; otherwise a fresh
  profile is downloaded before signing.
- The persisted machine-id is sent as machineId on every CSR, so Apple
  keeps one machine identity across certificates instead of a new UUID
  per request.
- TLS verification goes through the macOS system trust store via
  truststore, because certifi 2026.10.23 carries no Apple Root CA. That
  store also honors user and admin installed roots such as mkcert and
  mitmproxy, so a login must not run while an interception proxy is
  active. Safari and Xcode trust the same set.
- Non secrets under ~/Library/Application Support/sideload: cached
  App ID lists, team device lists, raw profiles, and install records
  (0700). The logs directory is reserved for diagnostics; v1 writes no
  command log. `sideload auth logout` deletes only the Keychain session.
- Untrusted input: extraction rejects absolute names, backslashes,
  parent traversal, and escaping symlinks; it bounds entry count and
  uncompressed size (50k entries, 1 GiB per entry, 4 GiB total),
  streams files to disk, strips setuid/setgid/sticky bits, and removes
  the work directory on exit. Repack writes through a temp file and
  os.replace, so a failed run cannot truncate the previous artifact.
- Apple requests refuse redirects, so a TLS intercepting proxy cannot
  replay the GS token or the 2FA code to another host.

## 6. Install mechanics and error surfacing

- Discovery/pairing: idevice_id -l, idevicepair validate/pair. The
  Trust dialog on the iPhone is a user action; the tool waits for it.
- Developer Mode: iOS 16+ refuses to run developer signed apps with
  it off. Read state with
  ideviceinfo -q com.apple.security.mac.amfi -k DeveloperModeStatus.
  Enabling it is a device Settings action that cannot be automated
  (and the tool says so plainly). Install may still succeed with
  Developer Mode off; launching will not.
- Install: ideviceinstaller -u <udid> install|upgrade <signed.ipa>
  (1.2.0 subcommands; the legacy -i/-g flags are detected and used on
  1.1.x). This drives the
  same com.apple.mobile.installation_proxy service AltStore drives
  directly: the IPA is staged over AFC into Public/Staging and an
  Upgrade command runs with the bundle id and version. Talking to the
  proxy directly (the pymobiledevice3 approach) gives structured
  progress plists (Status stages, PercentComplete) but costs the GPL
  library or a from scratch protocol stack; ideviceinstaller's output
  is a small, parseable stderr line format and keeps this project MIT,
  so it is the chosen backend. The DeviceAppClient interface is shaped
  so a future native proxy client can slot in without CLI changes.
- The proxy's structured Error names (from libimobiledevice
  installation_proxy.c and Apple TN2319) map to errors.py hints:
  ApplicationVerificationFailed (signature or profile rejected),
  BundleVerificationFailed, MismatchedApplicationIdentifierEntitlement
  (previously installed with a different team: uninstall first),
  PackageExtractionFailed, InsufficientDiskSpace,
  EmbeddedProfileInstallFailed, NotEntitled, InstallProhibited,
  APIInternalError.
- When the proxy error is not actionable, the real reason is in the
  device syslog: idevicesyslog filtered for installd, amfid, and
  AppleMobileFileIntegrity lines. `sideload doctor --follow-logs`
  streams those live.
- Uninstall is destructive. It requires an explicit `--yes` flag, never
  prompts, and the refusal is a distinct error class.

## 7. Signing mechanics that matter

- Bundle id: free teams cannot use wildcard App IDs, so the resigned
  id is `<original>.<TEAMID.lowercase()>` (AltStore's rule). App
  extensions take `<parent_resigned>.<extension>` and each consumes its
  own App ID against the 10 at a time quota. Every extension is
  provisioned independently: rewritten Info.plist id, its own App ID,
  its own downloaded profile and embedded copy, and entitlements built
  from that profile.
- Entitlements: the profile Entitlements dict is the base set. Keys the
  binary requests that the profile does not grant are dropped with a
  warning; --strict-entitlements turns drops into errors. Free and
  standard paid profiles never grant com.apple.private.* entitlements,
  so a nightly that requires them will install but be killed at launch
  by amfid. On stock iOS 17.6.1 there is no CoreTrust bypass; this is
  a hard Apple boundary, stated plainly.
- AltSign additionally merges "psychic paper" entitlements hidden in
  XML comments (marker "<!---><!-->" to "<!-- -->"); sideload extracts
  the same range when present.
- embedded.mobileprovision must be written into every bundle root
  (main app and each PlugIns extension) before sealing.
- Signing order: loose dylibs first, then framework binaries (deepest
  first), then extension bundles, then the main executable last.
  codesign produces _CodeSignature/CodeResources for the outer bundle;
  any file edited after the outer signature breaks the resource seal,
  which is the classic "invalid code signature" install failure.
- Info.plist: CFBundleIdentifier rewritten to the resigned id; App
  Store leftovers (SC_Info/, _MASReceipt/) removed.
- FairPlay encrypted App Store binaries cannot be re-signed usefully;
  detected and rejected as UnsupportedIPAError.

## 8. Error taxonomy

errors.py is the single taxonomy; the table maps raw failures to
classes (full class list and hints live in that module):

| Raw failure | Exception | Exit |
|---|---|---|
| bad CLI args | UsageError | 2 |
| wrong Apple ID password (GSA -22406) | AuthError | 1 |
| 2FA code rejected (GSA -21669) | TwoFactorError | 1 |
| session token expired or rejected | SessionExpiredError | 3 |
| AOSKit missing or silent | AnisetteError | 1 |
| resultCode 9120 App ID quota | AppIDQuotaExceededError | 1 |
| resultCode 9401/9412 bundle id | BundleIdentifierUnavailableError | 1 |
| resultCode 3250 CSR rejected | InvalidCertificateRequestError | 1 |
| resultCode 35 already registered | DeviceAlreadyRegisteredError | treated as success |
| profile older than now | ProfileExpiredError | 1 |
| UDID not in profile | DeviceNotProvisionedError | 1 |
| entitlements beyond profile | EntitlementsError (strict) | 1 |
| codesign/ldid failure | SigningError | 1 |
| Keychain denied or missing | KeychainError | 1 |
| missing external tool | TransportError | 1 |
| device not paired | PairingError | 1 |
| Developer Mode off | DeveloperModeDisabledError | 1 |
| proxy Error ApplicationVerificationFailed et al | InstallError | 1 |
| uninstall without --yes | UninstallConfirmationRequired | 2 |

## 9. Risks, unknowns, and what cannot be automated

- Apple's private APIs: GSA SRP, the QH65B2 action set, and resultCodes
  are undocumented and can change without notice. Mitigation: the
  protocol is isolated in two modules (auth.py, developer.py) and
  pinned to what AltSign and SideStore ship in production today.
- The 7 day wall: free profiles expire weekly; the tool must re-sign
  weekly and the session may outlive the profile or vice versa. There
  is no legal way around it. The cache is designed for cheap refresh
  (reuse App ID and certificate, re-download profile).
- Interactive steps that cannot be automated on a free account: the
  2FA code, the device Trust dialog, enabling Developer Mode, and the
  Keychain access prompt on first use. Each is surfaced as an explicit
  instruction, never silently worked around.
- Restricted entitlements: tools needing com.apple.private.* or
  unsandboxed capabilities will not launch on a stock device. The
  nightly acceptance case must therefore tolerate the free entitlement
  set (get-task-allow debugging included) or run on a device where
  those entitlements are otherwise granted. This is the single
  biggest acceptance risk.
- App ID quota: apps with several extensions consume quota fast
  (one App ID each). sideload warns before creating more than 5 new
  App IDs in one run.
- ipa diversity: watchOS companions, sticker packs, and on demand
  resources are inventory pitfalls; the bundle inventory must be
  driven by directory structure plus Mach-O magic, not file names.
- ldid licensing: AGPL. It is invoked only as a subprocess fallback;
  the repository never vendors its source.
- PyPI name "sideload" was unregistered at design time.
- Apple may rate limit or challenge automation on the developer
  portal endpoints; if that happens, nothing in this design can
  bypass it and the failure will be surfaced as DeveloperAPIError.

## 10. Auto refresh and the launchd agent

Free profiles expire 7 days after issuance, so a sideloaded app stops
launching after a week. The refresh slice automates what Sideloadly
automates: re-sign the app with the cached certificate, App ID, and
profile, download a fresh profile only when the cached one no longer
covers the team, device, or certificate, and install the result over
USB before the old profile dies.

Data flow for "sideload refresh [--udid UDID] [--all]":

1. Load the session from the Keychain. Missing, expired, or Apple
   rejected exits 3 before any further Apple call; the first call of
   the reused sign pipeline (fetchTeams) is the rejection canary.
2. Pick targets: --all is every device with install records, otherwise
   --udid, else the remembered default device, else the sole device
   with records (several is a usage error listing them).
3. List connected devices once. A device that is off, unpaired, locked,
   or has Developer Mode off is skipped with a message; its records
   survive untouched.
4. Per record: skip and report when no source IPA was recorded or the
   file is gone (records are never deleted automatically), or when the
   record belongs to another Apple ID (dsid mismatch); otherwise re-run
   the existing sign pipeline with the record's resigned bundle id, so
   the same App ID, bundle id, and cached profile are reused, then
   install the re-signed IPA from a per run temp directory and update
   the record's profile uuid.
5. Print one summary line per app plus a count line. Exit 0 only when
   every attempted app was refreshed; any failure, or nothing
   refreshable at all, is exit 1.

The daemon is a per user LaunchAgent, not a system daemon: no root, no
credential storage, and the same Keychain session as the terminal. The
plist (dev.sideload.refresh.plist in ~/Library/LaunchAgents, 0600 file,
0700 directory when created here) runs the current interpreter with
"-m sideload refresh --all" on a daily StartInterval with RunAtLoad
false, and writes stdout and stderr into the sideload logs directory
as refresh.log. install loads it with "launchctl bootstrap gui/<uid>"
and falls back to the legacy "launchctl load"; uninstall boots it out
and removes the plist; status reports the file and the launchd state.
All launchctl work goes through an injectable subprocess runner and
all paths are injectable, so tests never touch the real launchd or the
real ~/Library.

Security constraints of the background run, stated plainly: the agent
cannot prompt, so it can never log in, enter a 2FA code, or accept a
Trust dialog. It depends on a valid session token in the Keychain; on
expiry the refresh exits 3 and the log tells the user to run
"sideload auth login" in a terminal. The refresh log carries bundle
ids, file paths, dates, and error messages only; no token or password
ever reaches it.

## 11. Module ownership and implementation plan

Agents implement only their own files. Shared files (models, errors,
config) change only via agreement; their content is complete here
except trivial bodies.

| File | Owner | Work |
|---|---|---|
| src/sideload/models.py | shared | complete; add nothing |
| src/sideload/errors.py | shared | complete; add nothing |
| src/sideload/config.py | GLUE | resolve paths, ensure dirs, tool discovery |
| src/sideload/cache.py | GLUE | JSON mirrors, profile cache, install records |
| src/sideload/cli.py | GLUE | dispatch + exception to exit code mapping |
| src/sideload/keychain.py | AUTH | security CLI wrapper, session CRUD, p12 import |
| src/sideload/apple/anisette.py | AUTH | PyObjC loadBundle AOSKit/AuthKit, provider |
| src/sideload/apple/auth.py | AUTH | SRP-6a, s2k PBKDF2, 2FA, apptokens, session |
| src/sideload/apple/developer.py | SIGN | QH65B2 plist actions + v1 cert API |
| src/sideload/signing/csr.py | SIGN | keypair, CSR, machine identity |
| src/sideload/signing/profile.py | SIGN | security cms parse + validation |
| src/sideload/signing/entitlements.py | SIGN | extract, merge, drop, strict mode |
| src/sideload/signing/ipa.py | SIGN | unzip, inventory, plist edits, repack |
| src/sideload/signing/signer.py | SIGN | codesign and ldid backends, order |
| src/sideload/device/usbmux.py | DEVICE | subprocess wrappers for idevice tools |
| src/sideload/device/installer.py | DEVICE | ideviceinstaller driving, error mapping |
| src/sideload/daemon.py | GLUE | refresh loop helpers, plist generation, launchctl control |

Suggested implementation order: shared config and cache, then AUTH
(smallest blast radius, testable with any Apple ID), then DEVICE
(testable against the paired iPhone with a pre-made signed IPA), then
SIGN (largest), then CLI integration.

Estimated sizes: every module above fits in a few hundred lines; the
only heavy one is auth.py (SRP plus plist plumbing), estimated 400 to
500 lines.

## 12. Research sources (read, not summarized)

- AltSign (rileytestut/AltSign): Apple API actions, headers, resultCodes,
  SRP login, profile parsing, ALTSigner signing flow:
  https://github.com/rileytestut/AltSign
- AltStore and AltServer (rileytestut/AltStore): sideload pipeline,
  bundle id rules, AOSKit anisette, profile fetch operation:
  https://github.com/rileytestut/AltStore
- SideStore apple-private-apis (icloud-auth, omnisette): current Rust
  GSA SRP and anisette confirming the AltSign flow is still live:
  https://github.com/SideStore/apple-private-apis
- SideStore minimuxer: pairing and install context:
  https://github.com/SideStore/minimuxer
- ipatool (majd/ipatool): store bag and MZFinance auth, keychain
  session design, 2FA input handling; its SAP emulation is out of
  scope for this project: https://github.com/majd/ipatool
- pymobiledevice3 (doronz88/pymobiledevice3): installation_proxy
  service usage and structured error surfacing (GPL-3, not a
  dependency): https://github.com/doronz88/pymobiledevice3
- zsign (zhlynn/zsign): nested signing order and CodeResources rules:
  https://github.com/zhlynn/zsign
- ldid (saurik, Homebrew formula): pseudo-signing fallback, license
  AGPL-3.0-or-later: https://formulae.brew.sh/formula/ldid
- libimobiledevice and ideviceinstaller: usbmux, lockdown,
  installation_proxy error names and stderr formats:
  https://github.com/libimobiledevice/libimobiledevice
  https://github.com/libimobiledevice/ideviceinstaller
- Apple account limits (primary):
  https://developer.apple.com/help/account/basics/about-your-developer-account/
- Apple install failure background: TN2319, TN2242
  https://developer.apple.com/library/archive/technotes/tn2319/_index.html
