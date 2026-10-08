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
- A free Apple ID (a separate one just for sideloading is recommended).

## 1. Install the PC receiver

Download `iostransfer` (Linux) or `iostransfer.exe` (Windows) from the latest
[GitHub Actions run](https://github.com/Akay-74/iostransfer/actions/workflows/pc.yml) (artifact
`iostransfer-Linux` / `iostransfer-Windows`) or the [Releases](https://github.com/Akay-74/iostransfer/releases) page.

Or build it yourself (Rust 1.85+):

```bash
cd pc && cargo build --release -p iostransfer   # → pc/target/release/iostransfer
```

**Windows:** SmartScreen shows "unknown publisher" (the binary isn't code-signed; that costs money).
Click *More info → Run anyway*. On first run, allow it through Windows Firewall, or run once as administrator:

```
netsh advfirewall firewall add rule name=iostransfer dir=in action=allow program="C:\path\to\iostransfer.exe" enable=yes
```

**Linux (Fedora/Nobara):** the default firewalld zone already allows it. Elsewhere open TCP 47800 and UDP 5353.

## 2. Install the iPhone app (no Mac)

The app is built by GitHub Actions as an unsigned `IOStransfer.ipa`
([ios workflow](https://github.com/Akay-74/iostransfer/actions/workflows/ios.yml), artifact
`IOStransfer-ipa`). It is signed with your free Apple ID when you install it:

1. Install [iloader](https://github.com/nab138/iloader) (Linux: RPM/DEB/AppImage, needs the `usbmuxd`
   and `fuse` packages; also Windows/macOS).
2. Connect the iPhone by USB, trust the PC, and use iloader to install **SideStore** (it also writes the
   pairing file SideStore needs). Install **LocalDevVPN** from the App Store.
3. On the iPhone: Settings → Privacy & Security → **Developer Mode** → on (restart when asked).
4. Open SideStore → My Apps → **+** → choose `IOStransfer.ipa`.

Free Apple IDs sign apps for **7 days**; SideStore refreshes IOStransfer on the phone over Wi‑Fi
(LocalDevVPN), no PC trip needed. If a refresh ever fails (Apple changes break sideloading tools from
time to time), reinstall with iloader; your pairing and settings survive.

## 3. Pair (once)

On the PC:

```bash
iostransfer pair --dest ~/Pictures/iPhone
```

It prints a QR code and a pairing code like `7K3M-Q9TX`. In the app: set-up screen → **Scan the pairing
QR code**. Check that both screens show the **same code**, tap **Pair**, then type `y` on the PC.

## 4. Transfer

On the PC (leave it running):

```bash
iostransfer receive --dest ~/Pictures/iPhone
```

On the iPhone: pick **Photos** or **Videos**, open a collection (Recents, Screenshots, Selfies, Live
Photos, Portrait, any album…), and select:

- **Select** mode: tap photos, or **All** / **None** for the whole collection.
- **Range** mode: tap the first photo, scroll, tap the last; everything between is selected.
  Starting a range on an already-selected photo deselects instead.

Then **Copy** or **Move**. Keep the screen open while it runs (or enable the experimental
*Keep transferring when locked* in Settings).

### Options

| `receive` option | Effect |
|---|---|
| `--xmp` | Also write `<name>.xmp` sidecars (date, location, favourite) for copies. Moves always do: they preserve "Adjust Date & Location" edits, which live only in the Photos database |
| `--paranoid` | Before the phone deletes anything, re-hash every file on the PC (slower; catches disk corruption) |
| `--port N` | Listen on another port (default 47800). If you change it, pair with `iostransfer pair --receive-port N` so the iPhone knows |

`iostransfer devices list` / `iostransfer devices revoke <id>` manage paired iPhones.

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
| iPhone can't find the PC | Same Wi‑Fi? Guest networks often block devices from seeing each other. Windows: firewall rule above. Allow *Local Network* for IOStransfer in iPhone Settings → Privacy. |
| "another iostransfer is already using …" | Only one `receive` per destination folder. |
| "Pairing failed" | Run `iostransfer pair` again for a fresh QR code (codes expire after 10 minutes and work once). |
| Some items "kept on iPhone" after a move | They changed during the move, can't be deleted (e.g. synced from a computer), or failed verification. They are safe; run Move again. |
| Storage not freed after a move | Empty *Recently Deleted* in Photos. Spot-check the PC first. |
| App won't open after a week | The 7-day signature expired: refresh in SideStore. |

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
