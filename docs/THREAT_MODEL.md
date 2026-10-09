# IOStransfer — Threat Model (draft 0.1)

Scope: the phone app, the PC receiver, the protocol between them (PROTOCOL.md), pairing, and the build and
distribution chain. **Out of scope:** a fully compromised iPhone (jailbreak with root malware), and physical
attackers with forensic tools.

**The project's most valuable property is "never lose a photo".** Confidentiality matters, but a design
choice that trades a little privacy for delete safety wins.

---

## 1. Assets and what must be guaranteed

| # | Asset | Guarantee |
|---|---|---|
| A1 | Originals on the phone | Deleted **only** after a durable, verified copy exists on the user's own PC (PROTOCOL §10 safety argument) |
| A2 | Copies on the PC | Byte-identical to the phone's resources; never silently corrupted or overwritten with other content |
| A3 | Photo content and metadata (faces, GPS, times) in transit | Confidential and integrity-protected against the LAN |
| A4 | The PC itself | A peer on the LAN, paired or not, can't write outside the destination folder, run code, or exhaust the machine |
| A5 | Pairing secrets: PC private key, `device_secret` | Stay on the two devices; compromise is detectable and recoverable |

## 2. Trust boundaries

```
 [iPhone app] ──Wi‑Fi LAN (untrusted)──► [PC receiver] ──► [dest folder + index.db]
      │                                        ▲
      └──USB cable → usbmuxd (local OS service; any local process can use it)
 [QR code on the PC screen]  ── optical channel; can be photographed or replaced
 [GitHub repo / Actions / Releases] ──► .ipa (re-signed by SideStore) and PC binaries
```

## 3. Attackers

| Id | Attacker | Capabilities |
|---|---|---|
| L | LAN attacker | Same Wi‑Fi (café, guest network, flatmate). Can sniff, spoof mDNS and ARP, connect to any port, MITM TCP |
| Q | QR attacker | Can get the user to scan a QR code they made (social engineering, a sticker, a web page) |
| U | Local process on the PC (unprivileged) | Can talk to usbmuxd and connect to localhost ports; can read world-readable files |
| M | Malware with the user's privileges on the PC | Can read the dest folder, the key and index.db; can impersonate the receiver |
| T | Thief with the phone (locked or unlocked) | — |
| S | Supply chain | A compromised dependency, GitHub Action, or release artifact |

---

## 4. Threats and controls

Status: **D** = designed in (doc reference), **N** = new requirement from this document, **R** = residual risk accepted.

### T1 — Passive LAN sniffing (L) → A3

- **D:** TLS 1.3, no fallback, ALPN `iost/1` (PROTOCOL §1.1).
- **R:** mDNS reveals that an IOStransfer PC exists (`_iostransfer._tcp`, TXT `pcid`, `v`) and the phone's
  browse queries reveal app use. No content and no device names. Accepted.
- **N1:** Keep the TXT record minimal: no PC user name, no hostname beyond the default service instance name.
  The PC's friendly name travels only inside TLS (`WELCOME.pc_name`).

### T2 — LAN attacker impersonates the PC (L) → A1, A3

Goal: receive the user's photos, or fake `ACK durable` / `VERIFIED ok` so the phone deletes originals that were never stored.

- **D:** The phone pins the PC's SPKI from the QR (PROTOCOL §1.1). A spoofed Bonjour entry or ARP MITM fails the TLS
  pin. The PC must also produce `r_proof` with `device_secret` (§4.2), so it needs **both** the key and the secret.
- **N2:** A pin mismatch is a hard failure with the message "This isn't your paired PC". There's **no**
  "trust anyway" button. The only recovery is re-pairing by QR.
- **N3:** A pin mismatch never falls back to another address of the same `pcid` without a pin check (each
  address is pinned independently; there's no TOFU on any path).
- **R:** Spoofed mDNS can point the phone at a dead host, which is a DoS only. The phone tries the remaining addresses.

### T3 — LAN attacker or rogue paired phone attacks the PC (L) → A4, A2

Pre-auth surface: TCP accept, TLS handshake, the 8-byte preface, and one `HELLO` JSON frame.

- **D:**
  - Frame cap `MAX_FRAME_LEN` is checked from the 4 header bytes before any buffering (vector
    `len_max_plus_1_header_only`).
  - Handshake timeouts (PROTOCOL §7.3).
  - Auth rate limit: 5 failures per minute per source address (§4.2).
- **N4:** At most **8** concurrent un-authenticated connections. Further accepts are closed immediately.
- **N5:** The decoder fuzz target (proptest / cargo-fuzz) runs in CI on every PR: arbitrary bytes, then no panic,
  no allocation above `MAX_FRAME_LEN + 4`, and no infinite loop.

Post-auth, a malicious or buggy paired sender can still send hostile **content**:

- **N6 — Paths are never built from phone-supplied strings.** `original_filename`, `device_name`, `label` and
  `res_key` go through one sanitiser:
  - Take the stem only.
  - Reject or replace `/ \ : * ? " < > |`, NUL and control characters, leading `.`, and the names `.` and `..`.
  - Reject Windows reserved names and trailing dots or spaces.
  - Limit to 100 UTF-8 bytes.
  - The extension comes from a **UTI → extension allowlist** (`public.heic` → `.HEIC`, …; unknown → `.bin`),
    never from the filename.
  - After joining, the canonical path MUST start with the canonical dest dir (a belt-and-braces check).
  - `asset_id` is never used in paths (it contains `/`).
- **N7 — No symlink following in dest.** Create `.part` files with `create_new` (O_EXCL), so a pre-planted file
  is never overwritten. Before renaming, refuse if the target exists as a symlink or reparse point. Use
  `O_NOFOLLOW` where available.
- **N8 — Resource limits:**
  - `RES_BEGIN.size` ≤ 1 TiB and ≤ free space − reserve, else `RES_NACK{disk_full}`.
  - Open `.part` files per session ≤ `max_slots`.
  - The XMP sidecar is generated from typed values (numbers and dates), never by string-concatenating phone text into XML.
  - The LOG `msg` is printed with control characters escaped, so there's no terminal escape-sequence injection into the PC console.
- **N9 — JSON:** serde with typed structs (no `Value` for whole frames). The nesting depth limit stays at
  serde_json's default (128). Unknown fields are ignored.
- **R:** A paired phone can fill the disk up to the reserve. It's the user's own phone; `PAUSE` and a warning cover it.

### T4 — Malicious QR code (Q) → A1, A3

The attacker shows a QR with their own host and SPKI, so the phone pairs with the attacker's PC and sends
photos there. In a move job, the attacker's PC could even ACK and VERIFY and get the originals deleted (still
in Recently Deleted for 30 days).

- **N10 — No URL scheme.** The app does **not** register `iost://` as a URL scheme. A web page or message can't
  open a pairing link. Only the in-app camera scanner parses QR payloads.
- **N11 — Pairing confirmation on both ends.**
  - The phone shows "Pair with *pc_name* — code **A1EK-JAG0**". The code is the first **40 bits** of the SPKI
    pin in Crockford base32, 8 characters shown as `XXXX-XXXX` (PROTOCOL §4.1). 40 bits rather than 32 makes
    grinding a lookalike key about 256× harder.
  - `iostransfer pair` prints the same code and asks "Pair *device_name*? [y/N]" before sending WELCOME
    (hence the 60 s pairing timeout in PROTOCOL §7.3).
  - A QR scanned from a photo of someone else's screen therefore needs the attacker's PC, not the user's, to approve.
- **N12 — QR parser hardening:**
  - At most 8 hosts.
  - IP literals only (no DNS names). Hosts outside RFC 1918, 100.64/10, link-local and IPv6 ULA/link-local
    trigger an explicit warning ("This PC isn't on your local network").
  - Port 1–65535.
  - `spki` exactly 43 base64url characters; `t` 32 hex characters (128-bit token).
  - Total payload ≤ 1 KB. Unknown parameters are ignored.
- **N13 — First move to a new PC.** The first move job after pairing with a new PC asks for an extra
  confirmation: "Delete from iPhone after copying to *pc_name*?".
- **R:** A user who deliberately approves an attacker's PC on both screens isn't defended against.

### T5 — USB path: local processes and replay (U) → A1, A3

USB is plain TCP through usbmuxd (PROTOCOL Δ13). Any local process can open a connection to the phone's
port via usbmuxd. On Linux the socket is usually world-accessible, and on Windows it's `localhost:27015`.

- **D:** Mutual HMAC challenge-response with fresh 256-bit nonces from **both** sides (§4.2). The phone verifies
  `r_proof` **before sending any data**, so a local process without `device_secret` gets nothing. Recorded
  proofs can't be replayed, because each session has a fresh `s_nonce`.
- **N14 — Listener exposure:** the phone's USB listener is bound to **loopback only** and exists only while
  USB mode is on (PROTOCOL §1). Otherwise a plaintext listener would be reachable from the Wi‑Fi LAN. The R8 spike confirms that usbmux traffic arrives via loopback.
- **R:** After auth the USB stream has no encryption or integrity. Reading or injecting into an existing usbmux
  stream needs control of usbmuxd itself (root/admin, or attacker M). At that level the attacker already
  owns the destination folder, so we accept this.
- **R:** No channel binding between the HMAC proofs and the transport, so a relay is possible in principle. Over
  Wi‑Fi the SPKI pin prevents it; over USB the relay would have to be usbmuxd. Channel binding (TLS exporter) is a v2 candidate.

### T6 — Lost or stolen phone (T) → A5

- **D:** `device_secret` and `device_id` live in the Keychain with `AfterFirstUnlockThisDeviceOnly`: not in
  backups and not migratable. Spool files have the same protection class as the rest of the app's data.
- **N15:** `iostransfer devices revoke <device_id>` deletes the device row and its secret. The phone's next handshake gets
  `unknown_device`.
- **R:** A thief with an unlocked phone can send that phone's photos to the user's own PC. That's harmless and arguably helpful.

### T7 — Malware on the PC, or a stolen PC (M) → A1, A2, A5

- **D (partial):** Recently Deleted keeps moved originals for 30 days. That's the backstop against a receiver
  that lies about durability.
- **N16:** The PC key file and `index.db` are created with owner-only permissions (0600 on Linux, an owner-only
  ACL on Windows). The receiver refuses to start if the key file is group- or world-readable.
- **N16a:** The PC must store the **raw** `device_secret` (HMAC needs it), so the `devices` table lives in the
  per-user **config dir** next to the TLS key, **not** in `<dest>/.iostransfer/index.db`. The destination is often
  an exFAT/NTFS external drive or a NAS share where permissions can't be enforced, and it travels with the
  photos.
- **N17:** The phone's Done screen for a move shows "Copied *n* files, *X* GB to *pc_name*". Suggested habit: spot-check
  on the PC before emptying Recently Deleted. `iostransfer verify --rehash` re-checks every file against the
  stored SHA-256.
- **R:** Malware with the user's privileges can read every received photo, impersonate the receiver (key +
  secrets are on disk), or tamper with copies. Full-disk encryption and general PC hygiene are the user's
  responsibility; the README says so.

### T8 — Supply chain (S) → everything

- **N18:**
  - GitHub Actions are pinned by **commit SHA**, not tag.
  - Workflows use `permissions: contents: read`; only the release job gets `contents: write`, and only on tags.
  - CI has no secrets at all (unsigned builds).
- **N19:**
  - `cargo-deny` (advisories, licenses, sources = crates.io only) and `Cargo.lock` are committed.
  - Swift packages are pinned with `exact:` versions plus `Package.resolved`.
  - Dependabot runs weekly.
- **N20:** Every release publishes `SHA256SUMS` for the `.ipa` and PC binaries. The README shows how to check
  them, which matters more because users must click through SmartScreen "unknown publisher".
- **R:** SideStore and iloader are third-party tools trusted with the Apple ID session. Recommend a
  **dedicated free Apple ID** for sideloading, not the user's main one.

### T9 — Downgrade and version confusion (L)

- **D:** Version negotiation happens inside TLS on Wi‑Fi; an attacker can't change `proto`.
- **N21:** Neither side implements any protocol version below 1, and there's no "plaintext mode" except
  `--insecure-dev`, which binds to 127.0.0.1 only and prints a red warning.

### T10 — Accidental data loss (no attacker) → A1

This is the most likely threat, so it's listed here even though it isn't adversarial. Controls (all **D**):
- Unit of commit = asset.
- `synchronous=FULL` plus fsync, rename, and dir-fsync before ACK.
- Hash verified at receipt.
- VERIFY against the phone's current resources and meta (PROTOCOL Δ10, Δ14, Δ18).
- Pre-delete guards, including `canPerform(.delete)` and the fingerprint.
- `delete_batch` write-ahead.
- The crash matrix (PROTOCOL §10).
- iCloud-off check per asset (`notLocal` blocks the move).
- Recently Deleted.

**N22:** CI runs a crash-injection test on the Rust receiver. The `IOST_CRASH_AT=<P1..P4>` env hook aborts the
process at each crash point of PROTOCOL §10. After restarting, the interop test must reach the same final
state with no `.part` leftovers and no ACK without a durable file.

### T11 — The PC signs and installs the iPhone app (guided mode) → Apple ID, A5

The guided mode (`iostransfer` with no arguments) signs the app with the user's free Apple ID and
installs it over USB, then renews it every few days over USB or Wi‑Fi. That adds new secrets on the PC
and a new way into the phone.

- **N23 — Apple ID password:** stored only in the OS credential store (Windows Credential Manager, the
  Secret Service keyring on Linux), never in a file. It is sent only to Apple: sign-in is SRP via
  `isideload`, so the anisette helper server (`ani.stikstore.app`, which provides Apple's
  device-attestation headers) never sees it. A failed sign-in deletes the stored password. A separate
  Apple ID just for sideloading is recommended.
- **N24 — Lockdown pairing records:** the iPhone's "Trust This Computer" record is copied to
  `<config>/phones/<udid>.plist` (owner-only) for Wi‑Fi renewal. Whoever holds it can use the
  phone's lockdown services on the LAN (install apps, read some device info), exactly like iTunes'
  own copy. `<config>` must stay private (N16); "Settings → General → Transfer or Reset iPhone →
  Reset Location & Privacy" on the iPhone revokes it.
- **N25 — What gets installed:** release binaries embed the `.ipa` built by the same tagged CI run
  (no download). Development builds download the latest release's `.ipa` over HTTPS and check it
  against that release's `SHA256SUMS` (this catches corruption, not a compromised release).
- **N26 — No renewal during a transfer:** installing restarts the app, so renewal runs only while no
  session is open.

---

## 5. Requirements summary (for the backlog)

| Id | Requirement | Owner area | Milestone |
|---|---|---|---|
| N1 | Minimal mDNS TXT | PC | M1 |
| N2, N3 | Hard pin failure, no TOFU, no fallback without pin | iOS | M2 |
| N4 | ≤ 8 pre-auth connections | PC | M1 |
| N5 | Decoder fuzzing in CI | PC/CI | M1 |
| N6 | Path sanitiser + UTI extension allowlist + canonical-prefix check | PC | M1 |
| N7 | `create_new` `.part`, no symlink/reparse following | PC | M1 |
| N8 | Size/fd limits, typed XMP writer, escaped LOG output | PC | M1–M4 |
| N9 | Typed serde structs | both | M1 |
| N10 | No `iost://` URL scheme | iOS | M2 |
| N11 | Pairing code on both screens + PC y/N | both | M2 |
| N12 | QR parser limits and non-private-IP warning | iOS | M2 |
| N13 | First-move-to-new-PC confirmation | iOS | M4 |
| N14 | USB listener on loopback, only in USB mode | iOS | M6 |
| N15 | `devices revoke` | PC | M2 |
| N16, N16a | Owner-only key/DB permissions, refuse if too open; device secrets in the config dir, not dest | PC | M1 |
| N17 | Done-screen summary, `verify --rehash` | both | M4 |
| N18–N20 | CI hardening, cargo-deny, pinned deps, SHA256SUMS | CI | M0–M1 |
| N21 | `--insecure-dev` loopback-only | PC | M1 |
| N22 | Crash-injection test | PC/CI | M1 |
| N23–N26 | Apple ID in OS keyring, private pairing records, embedded .ipa, no renewal mid-transfer | PC | M7 |
