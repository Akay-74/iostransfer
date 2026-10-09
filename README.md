# IOStransfer

Copy or move thousands of photos and videos from an iPhone to a Windows or Linux PC over Wi‑Fi, as
untouched originals (HEIC, HEVC, ProRAW, Live Photos, edits included). No Mac, no App Store, no cost.

- **Copy**: everything you select lands on the PC, byte-identical, organized as
  `<folder>/<iPhone name>/Photos|Videos/YYYY/MM/`.
- **Move**: after the PC has verified every file, the iPhone deletes them in one batch (one system
  prompt). Deleted items stay in *Recently Deleted* for 30 days.
- Interrupted transfers resume where they stopped; nothing is ever sent twice.

## What you need

- An iPhone with **iCloud Photos turned off** (Settings → your name → iCloud → Photos). With iCloud
  Photos on, deleting on the iPhone deletes everywhere, so IOStransfer requires it off.
- A PC on the same Wi‑Fi/LAN, running Linux or Windows.
- A free Apple ID (a separate one just for sideloading is recommended) and a USB cable (first time only).

## Install and set up (one program, double-click)

**Windows:** download `IOStransfer-windows-x86_64.exe` from the
[latest release](https://github.com/Akay-74/iostransfer/releases/latest) and double-click it.
SmartScreen says "unknown publisher" (code signing costs money): click *More info → Run anyway*.

**Linux:** download `IOStransfer-linux-x86_64.tar.gz`, extract it, and double-click `iostransfer`
(or run `./iostransfer` in a terminal). It opens its own terminal window.

The program then walks you through everything, one time:

1. **Firewall.** Windows asks once for permission (click *Yes*). On Linux it asks for your password only if
   the firewall blocks it.
2. **The iPhone app.** Plug the iPhone in with a USB cable and unlock it. On Windows the program first
   offers to install Apple's iPhone driver (it comes with iTunes, from Apple, free). Tap **Trust** on the
   iPhone, then type your **Apple ID** and password, plus the verification code Apple sends. Any free
   Apple ID works; a separate one just for this is safer. The password is kept in Windows Credential
   Manager or the Linux keyring, never in a file.
   Then, on the iPhone:
   - Settings → Privacy & Security → **Developer Mode** → on, restart, confirm *Turn On*.
   - Settings → General → **VPN & Device Management** → your Apple ID → **Trust**.
3. **Pairing.** Open IOStransfer on the iPhone, finish its short setup (iCloud Photos off, allow
   Photos), tap **Scan the pairing QR code** and point it at the QR code in the PC window. Check that
   both screens show the **same code**, then type `y` and press Enter on the PC.

After that, just double-click the program whenever you want to transfer. Leave its window open: it
receives photos and renews the iPhone app before it expires. Free Apple IDs sign apps for 7 days; the
PC renews after 4 days, over USB or over Wi‑Fi whenever the iPhone and PC are on the same network.
If it's ever about to run out, the iPhone app shows a banner.

Commands in the PC window (type the letter, press Enter): **P** pair another iPhone, **I** install or
renew the iPhone app over USB, **O** open the photos folder, **D** change the folder, **Q** quit.

Photos go to `Pictures/iPhone` unless you change it with **D** (or start with `--dest <folder>`).

**Already use SideStore?** `IOStransfer.ipa` is in every release: install it with SideStore as usual and
press Enter at step 2 to skip the USB install.

## Transfer

On the iPhone: pick **Photos** or **Videos**, open a collection (Recents, Screenshots, Selfies, Live
Photos, Portrait, any album…), and select:

- **Select** mode: tap photos, or **All** / **None** for the whole collection.
- **Range** mode: tap the first photo, scroll, tap the last; everything between is selected.
  Starting a range on an already-selected photo deselects instead.

Then **Copy** or **Move**. Keep the screen open while it runs (or enable the experimental
*Keep transferring when locked* in Settings).

## Command line (advanced)

The same program has subcommands for scripts and servers:

```bash
iostransfer pair --dest ~/Pictures/iPhone      # pairing QR only
iostransfer receive --dest ~/Pictures/iPhone   # receive only (no setup, no renewal)
iostransfer devices list | revoke <id>
```

### Options

| `receive` option | Effect |
|---|---|
| `--xmp` | Also write `<name>.xmp` sidecars (date, location, favourite) for copies. Moves always do: they preserve "Adjust Date & Location" edits, which live only in the Photos database |
| `--paranoid` | Before the phone deletes anything, re-hash every file on the PC (slower; catches disk corruption) |
| `--port N` | Listen on another port (default 47800). If you change it, pair with `iostransfer pair --receive-port N` so the iPhone knows |


## What you get on the PC

```
~/Pictures/iPhone/<iPhone name>/Photos/2024/03/20240314_111522_IMG_4821.HEIC
                                              20240314_111522_IMG_4821.MOV          (Live Photo motion)
                                              20240314_111522_IMG_4821_edited.JPG   (your edit)
                                              20240314_111522_IMG_4821.AAE          (edit recipe)
                                              20240314_111522_IMG_4821.xmp          (moves: date/location/favourite)
~/Pictures/iPhone/<iPhone name>/Videos/2024/03/20240314_103001_IMG_4830.MOV
```

Files keep the photo's capture time as their modification time. Name clashes get `_2`; an existing
file is never overwritten. The PC never deletes anything.

## Troubleshooting

| Problem | Fix |
|---|---|
| iPhone can't find the PC | Same Wi‑Fi? Guest networks often block devices from seeing each other. Windows: restart the program and click *Yes* at the firewall prompt. Allow *Local Network* for IOStransfer in iPhone Settings → Privacy. |
| "Untrusted Developer" when opening the app | Settings → General → VPN & Device Management → your Apple ID → Trust. |
| App won't open, no Developer Mode switch | Plug the iPhone in with the PC program open and type `I`: installing reveals the switch. |
| Apple ID: "maximum number of certificates" | Pick an old one to revoke when asked (apps signed by it, e.g. via SideStore, stop opening until re-signed). |
| "port 47800 is in use" | IOStransfer is already open in another window. |
| "another iostransfer is already using …" | Only one `receive` per destination folder. |
| "Pairing failed" | Type `P` in the PC window for a fresh QR code (codes expire after 10 minutes and work once). |
| Some items "kept on iPhone" after a move | They changed during the move, can't be deleted (e.g. synced from a computer), or failed verification. They are safe; run Move again. |
| Storage not freed after a move | Empty *Recently Deleted* in Photos. Spot-check the PC first. |
| App won't open after a week | The signature expired: open the PC program with the iPhone plugged in (it renews automatically), or refresh in SideStore if you use that. |

## How it works

`docs/` holds the design: [ARCHITECTURE](docs/ARCHITECTURE.md), the byte-exact
[PROTOCOL](docs/PROTOCOL.md), the [THREAT_MODEL](docs/THREAT_MODEL.md), the Swift engine spec
[TRANSFERCORE](docs/TRANSFERCORE.md), and the on-device experiments in [SPIKES](docs/SPIKES.md).

- `pc/`: the Rust receiver (TLS 1.3, crash-safe writes with fsync checkpoints and startup recovery).
- `ios/TransferCore/`: the phone's engine, a deterministic state machine tested on Linux.
- `ios/App/`: the iOS app (SwiftUI, UIKit grid, PhotoKit, Network.framework).
- `tests/interop.sh`: the Swift engine against the real receiver: copy, resume after a receiver
  crash, and a full move.

Security in one paragraph: pairing pins the PC's key (shown as the pairing code on both screens); every
later connection is TLS 1.3 to that exact key plus mutual HMAC authentication, so neither a fake PC nor
a fake phone gets in. See the threat model for details and limits.
