# IOStransfer — Spike Plan (M0–M2, plus R4/R5/R8 later)

Measurements to take on the user's real iPhone and PC **before** building UI. For each risk R1–R10
(ARCHITECTURE §6): what to run, what to record, the pass/fail threshold, and which design decision the
result changes. A spike that doesn't change a decision isn't worth running.

---

## 0. Infrastructure

### 0.1 No separate spike app

The spikes run from a hidden **Diagnostics** screen inside the main app, with the same bundle ID
(open it with a 5-tap on the version label). A separate spike app would use one of the **3 sideload slots** and
one of the **10 App IDs per week** (ARCHITECTURE §5). Diagnostics code sits behind `#if DIAGNOSTICS`, and
that flag stays on in all builds until v1.0.

### 0.2 Output

- Each spike writes JSON Lines to `Documents/spikes/<R#>-<ISO time>.jsonl`. The first line records the environment:
  ```json
  {"spike":"R1","device":"iPhone15,3","ios":"19.1","app":"0.1.0","thermal":"nominal",
   "battery":0.82,"low_power":false,"assets_total":23817,"photos":21022,"videos":2795}
  ```
- When a PC session is up, the same lines also go out as `LOG` frames with `msg` = the JSON, and
  `iostransfer receive --log-dir` saves them. There's also a share button for the `.jsonl` file (one small
  file, so the share sheet is safe).
- The user fills in manual context: AP band (2.4/5/6 GHz), rough distance to the AP, and the PC's NIC (wired or Wi‑Fi).

### 0.3 PC side: `iostransfer spike-sink`

A small subcommand in the receiver crate, built in M1:

```
iostransfer spike-sink --port 47899 [--tls] [--log-dir DIR]
```

It accepts N connections, reads and discards everything, and logs bytes received per second per connection
with **PC timestamps**. The PC log is authoritative for anything measured while the phone may be suspended (R5).
`--tls` uses the same cert, ALPN and pinning as the real receiver.

### 0.4 Method

- Throughput: 5 s warm-up (discarded), then 60 s measured. 3 runs; report the **median** and min/max.
- Per-asset timings: p50, p90, p99 and max, using `ContinuousClock`.
- Phone CPU: `getrusage(RUSAGE_SELF)` user+sys time per run ÷ wall time.
- Memory: `os_proc_available_memory()` sampled at 1 Hz; report the minimum.
- Run with the screen on, the phone charging, and Low Power Mode off, unless the spike says otherwise.
  Record thermal state at start and end. If it reaches `.serious`, the run is marked invalid and repeated after a cool-down.

### 0.5 Order (some spikes need others first)

| Order | Spike | Needs | Duration |
|---|---|---|---|
| 1 | R7 sideload | — | ~1 h, plus a 7-day check |
| 2 | **R9 baseline snapshot** (starts a 24 h window) | R7 | 5 min, then 24 h |
| 3 | R10, R3 | R7 | 15 min |
| 4 | R1, R6 | R7 | 30 min |
| 5 | R2 | R7 + spike-sink | 30 min |
| 6 | R9 diff | snapshot + 24 h | 10 min |
| 7 | R4 (deletes synthetic assets only) | R7 | 20 min |
| 8 | R5 | R2 | 45 min |
| 9 | R8 | M6 | 1 h |

---

## R7 — Sideloading from Linux (M0)

**Steps (Nobara):**
1. `dnf install usbmuxd fuse`, then `systemctl start usbmuxd`.
2. Install iloader (RPM from GitHub releases).
3. Plug in the phone and trust the PC.
4. Use iloader to install SideStore and write the pairing file, then install LocalDevVPN from the App Store.
5. In SideStore, add our IPA from the GitHub Release URL.
6. On day 6, refresh in SideStore over Wi‑Fi with the USB cable unplugged.

**Record:**
- Success or failure, with the exact error at each step.
- App IDs used: SideStore + our app.
- The `Bundle.main.bundleIdentifier` reported at runtime (is the team ID appended?).
- Whether the Info.plist keys survived re-signing: `NSLocalNetworkUsageDescription`, `NSBonjourServices`, `UIBackgroundModes`.
- Whether a Keychain write and read works.
- Whether the Local Network prompt appears.

**Pass:**
- The app launches.
- The keys are present.
- The Keychain works.
- On-device refresh succeeds without the PC on day 6.

**Decision:**

| Result | Install path |
|---|---|
| Pass | iloader → SideStore + LocalDevVPN, as in ARCHITECTURE §5 |
| On-device refresh fails | iloader direct install, repeated weekly; README describes the weekly ritual |
| iloader fails on Linux | Windows + Sideloadly. Downgrades "Linux-only user" support; tell the user right away |
| Bundle ID suffixed | Confirms the runtime-derived Keychain service rule. No change, but it gets a test |

---

## R9 — Does `modificationDate` move without edits? (PROTOCOL Δ14, O5)

Start this early, because the window is 24 h.

**Snapshot (t0):** for every asset in the library, store
`{id, modified_ms, creation_ms, location?, favorite, fingerprint}`, where fingerprint = PROTOCOL §6.4 canonical form.
To keep it cheap, compute the fingerprint only for a 500-asset random sample, plus every asset that has `adjustment_data`.

**Controlled actions:** the user does these right after the snapshot and writes down the asset IDs (the
Diagnostics screen has a "mark next N tapped assets" helper):

| Set | Action | Count |
|---|---|---|
| E1 | Crop or exposure edit on a photo | 10 |
| E2 | Trim a video | 5 |
| E3 | Change the key photo of a Live Photo | 3 |
| E4 | Revert an edited photo to original | 3 |
| E5 | Adjust date & time | 3 |
| E6 | Adjust location | 3 |
| F | Toggle favourite | 10 |
| A | Add to an album | 10 |
| V | Only view full-screen, swipe through | 50 |
| C | Control: untouched | the rest |

Then the user uses the phone normally for 24 h, including one overnight charge, since Photos' analysis runs while charging and locked.

**Diff (t0 + 24 h):** for each set, count the assets with modified_ms changed, fingerprint changed,
creation_ms changed and location changed.

**Pass/fail and decisions:**

| Observation | Decision |
|---|---|
| Every E1–E6 and F asset changed **both** modified_ms and fingerprint (the fingerprint includes meta: date, location, favourite, PROTOCOL Δ18) | Keep the §8.4 shortcut ("modified unchanged ⇒ fingerprint unchanged") |
| Any E1–E6/F asset changed fingerprint but **not** modified_ms | **Remove the shortcut**: always recompute the fingerprint before deleting (PROTOCOL O5) |
| Any E1–E4 asset changed modified_ms but not fingerprint | Fingerprint is too weak. Add `sha256` of the render (`full_size_*`) to the fingerprint |
| C or V assets changed modified_ms | Confirms Δ14. Exact modified_ms must never be a delete criterion |
| Zero C/V/F/A changes in 24 h | Exact modified_ms MAY be added back as an extra guard |
| E5/E6 resource bytes unchanged (expected) | Confirms the metadata-edit finding: the original's EXIF keeps the old date/GPS. Already designed (ARCHITECTURE §2.8, PROTOCOL Δ18): meta is in the fingerprint, and move jobs write an **XMP sidecar** when PhotoKit's values differ from EXIF/QuickTime |
| E5/E6: the PC can't reliably read EXIF/QuickTime date or GPS from some formats (check every sample type from R3 with the PC's EXIF reader) | Move jobs write the XMP sidecar **always**, without comparing |
| E5/E6 resource bytes **did** change | The sidecar is redundant for those edits but harmless; keep it |

---

## R10 — Cost of `assetResources(for:)` and friends at library scale

**Measure** (whole library, in creation-date order, single thread, then 2 threads):
- `PHAssetResource.assetResources(for:)` per asset: p50, p99, total.
- The KVC `value(forKey: "fileSize")` per resource: p50, p99.
- `PHAsset.fetchAssets(withLocalIdentifiers:)` for batches of 1,000 IDs, as used by VERIFY and the pre-delete guard.
- Time to build one 500-asset MANIFEST page, including JSON encode, and its encoded size in bytes.

**Thresholds (extrapolated to 100,000 assets):**

| Total for 100k | Decision |
|---|---|
| < 60 s | Δ16 omission is a nicety; no resource-list cache |
| 60–300 s | Δ16 omission is required (already specified); no cache |
| > 300 s | Also cache resource lists in the journal keyed by `(asset_id, modified_ms)`, and build MANIFEST pages from the cache |

Also:
- A page larger than 512 KiB → lower the page size to 250 assets.
- KVC fileSize missing for any resource type → feeds O6/R3.

---

## R3 — Resource lists of special assets (and the O3/O6 checks)

**Find samples:**
- Use smart albums and subtypes: Live, Portrait (`smartAlbumDepthEffect`), Slo-mo, Time-lapse, Cinematic,
  Panorama, Screenshot, Screen recording, Spatial, Bursts.
- RAW: UTI `com.adobe.raw-image` (ProRAW), and assets that have both `.photo` and `.alternatePhoto` (RAW+JPEG).
- Edits: edited photo, edited video, edited Live Photo (via `adjustment_data` present).
- Imported: assets from other apps (non-camera `originalFilename` patterns).
- Shared album items (`sourceType == .typeCloudShared`), if Shared Albums are on.
- Up to 3 of each. Missing categories are listed as "not in library". The user can shoot samples on the spot (1 of each).

**Record per resource:**
- `type` raw value and name, `uti`, `originalFilename`, and the KVC `fileSize`.
- The **exported byte count** from `writeData`, plus the export time.

**Burst check (O3):** count assets with `burstIdentifier != nil` in three fetches:
- `smartAlbumBursts` with default options.
- The same with `includeAllBurstAssets = true`.
- A library-wide fetch with `includeAllBurstAssets = true`.

For one burst, compare `fetchAssets(withBurstIdentifier:)` against what's in Recents.

**Pass/fail and decisions:**

| Observation | Decision |
|---|---|
| A resource type not in ARCHITECTURE §2.5 | Add a row. It's already sent (unknown → send, edit family), so this only documents it |
| `photo_proxy` the only photo-ish resource of some asset | **Stop:** that asset has no original locally (iCloud remnant). Treat as `notLocal` |
| KVC fileSize == exported bytes for **100%** of resources | O6 closed: VERIFY of `have` assets uses KVC sizes |
| Any mismatch or missing KVC size | O6 fallback: `have` assets in move jobs are re-exported and hashed in the VERIFY phase. Costs time, not safety |
| `includeAllBurstAssets` adds frames inside `smartAlbumBursts`/collection fetches | The resolver uses it everywhere |
| It only works library-wide | When a selected asset has a `burstIdentifier`, the resolver expands it via `fetchAssets(withBurstIdentifier:)` |

---

## R1 — Export concurrency (`writeData`), with `requestData` as a baseline

**Input:** 1,000 photos (most recent, local) and the 10 largest videos.

**Runs:**
- `writeData` into the spool with N = 1, 2, 3, 4 and 6 concurrent exporters. Report MB/s and assets/s.
- `requestData` with the bytes discarded at the same N values: the read-only ceiling.

Delete the spool between runs. Photos and videos are measured separately.

**Decision:**
- Exporter count per lane = the smallest N that reaches ≥ 90% of the best MB/s for that lane.
  Today it's 2 photo + 1 video, so update ARCHITECTURE §2.6 if the result differs.
- If photo export MB/s at the chosen N is < **1.5×** the R2 single-stream network MB/s, export is the bottleneck.
  Enable the in-memory `requestData` path for photos < 50 MB (ARCHITECTURE §2.6 "later optimisation").
  In-memory photos skip the spool, so a kill means a re-export: acceptable for small files.

---

## R6 — Spool overhead per asset

**Input:** the same 1,000 photos and 10 videos. Run the full spool pipeline against `spike-sink --tls`:
export, then read with hashing, then send.

**Record per asset:**
- `export_ms`, `send_ms`, bytes.
- Peak spool bytes.
- Pipeline efficiency = `bytes / wall time` ÷ the R2 single-stream ceiling.
- Total flash written, roughly 2× the bytes sent. Recorded so we can tell the user.

**Pass/fail:**
- Pass: pipeline efficiency ≥ 85% of the R2 ceiling, and peak spool ≤ the budget (`min(2 GB, 10% free)`).
- Fail on efficiency → apply the R1 in-memory path, or raise the export look-ahead (export 2 assets ahead per lane).
- Fail on spool size → lower `max_unacked_bytes` on the phone side. That means the receiver's ACK latency is too high: investigate fsync batching.

---

## R2 — One TLS stream vs the link

**Runs** (against `spike-sink`, 3 × 60 s each):

| Run | Setup |
|---|---|
| a | Raw TCP, 1 stream |
| b | Raw TCP, 4 streams (baseline ceiling) |
| c | TLS 1.3, 1 stream, 256 KiB DATA frames (the real framing) |
| d | TLS, 2 streams |

Data comes from an in-memory buffer, not PhotoKit, so this isolates the network. Record phone CPU % for c.
Run near the AP (same room), and once from a far room.

**Pass/fail and decisions:**

| Observation | Decision |
|---|---|
| c ≥ 80% of b | Keep the single connection (ARCHITECTURE §3.3) |
| c < 80% of b but d ≥ 80% | Use 2 connections: photo lane and video lane each get their own, each with its own TLS session (both authenticated with §4.2; ACKs per connection) |
| c CPU > 60% of one core | Check the chunk size (try 1 MiB DATA frames: MAX_FRAME_LEN allows it) before adding connections |
| Far-room c < 10 MB/s | No design change; the UI shows a "move closer to the router" hint below a measured rate |

---

## R4 — Large `deleteAssets` batches (synthetic assets only)

**Safety:** this spike deletes **only assets it created itself**. It creates them in an album
"IOStransfer Spike", stores their localIdentifiers in `spikes/R4-created.json`, and the delete code accepts
only IDs from that file. It never touches the user's own photos.

**Steps:**
1. Create 100 + 1,000 + 5,000 tiny JPEGs (64×64, unique pixel noise, about 2 KB each, about 12 MB total) via `PHAssetCreationRequest`.
2. Delete each group with **one** `performChanges { deleteAssets(group) }`. The user confirms right away.
3. Record: time from call to completion; minimum available memory; whether one system prompt appeared and what it said; errors.
4. Mixed batch: 10 synthetic assets + 1 asset with `canPerform(.delete) == false`. Use a shared-album asset if one exists, otherwise skip this check. Record whether the whole batch fails.
5. Manual: confirm the assets are in Recently Deleted, then empty it.

**Pass/fail and decisions:**

| Observation | Decision |
|---|---|
| 5,000 completes in < 30 s, no jetsam, one prompt | One batch per job (ARCHITECTURE §2.8) |
| Slow or memory pressure at 5,000 but fine at 1,000 | Batches of 2,000, one prompt each |
| Fails at 1,000 | Batches of 500, and ask the user once, then iterate the prompts |
| Mixed batch fails entirely | Confirms the mandatory `canPerform` filter (PROTOCOL §8.4) |
| Mixed batch partially succeeds | Keep the filter anyway; note the behaviour |

---

## R5 — Background keep-alive while locked (experimental mode)

**Precondition:** R7 shows that `UIBackgroundModes = audio` survived re-signing and the app installed.
If the install was rejected with the key present, R5 fails immediately.

**Steps:**
1. Turn on silent audio (`AVAudioSession` `.playback` + `.mixWithOthers`, a looping silent buffer).
2. Start an R6-style pipeline to `spike-sink`: PhotoKit export plus TLS send of 200 photos and 3 videos.
3. Lock the phone at t = 60 s. Leave it locked for 10 min.
4. During the lock, at t = 3 min, play music from another app for 30 s. At t = 6 min, place a phone call or start Siri for 20 s.
5. Unlock at t = 11 min.

**Record:**
- PC-side bytes per second (authoritative).
- Phone-side `writeData` success or failure while locked, with error codes.
- Interruption begin and end events, and whether the transfer resumed.
- Battery % drop over the 10 min.

**Pass:**
- Bytes keep flowing for ≥ 9 of the 10 locked minutes.
- Locked throughput ≥ 50% of unlocked.
- Exports succeed while locked.
- The transfer resumes ≤ 10 s after each interruption ends.

**Decision:**

| Result | Decision |
|---|---|
| Pass | Ship the opt-in "experimental background mode" (ARCHITECTURE §2.7, M5) |
| Transfer continues but exports fail while locked | Spool look-ahead: export ahead while unlocked, up to the spool budget, so locked time only sends. The UI warns that background sending stops when the spool runs out |
| Suspended within minutes, or other failure | Remove `UIBackgroundModes`. Foreground-only; keep pocket mode |

---

## R8 — USB via usbmuxd (M6)

**Setup:** the Diagnostics screen starts an `NWListener` on device port 47801 running an echo/sink. On the PC, a
throwaway binary uses the `idevice` crate.

**Linux (`/var/run/usbmuxd`):**
1. List devices.
2. Connect to device port 47801.
3. Send 1 GiB.
4. Record MB/s (3 runs).

**Windows (Apple Devices or iTunes installed):** the same, via `localhost:27015`.

**Also record:**
- Whether usbmux connections reach a listener **bound to 127.0.0.1 only** (THREAT_MODEL T5). If they
  don't, record which local address they arrive on. The plaintext USB listener must not be reachable over Wi‑Fi.
- Whether the phone shows a Local Network prompt for usbmux connections.
- Whether the listener survives the screen locking (expected: no, without R5).
- Behaviour when the cable is pulled mid-transfer (time to detect on both ends).

**Pass:**
- Connect and transfer on both OSes.
- Throughput ≥ 30 MB/s, or ≥ 80% of the R2 Wi‑Fi rate, whichever is lower.
- A pulled cable is detected in ≤ 5 s on the PC.

**Decision:**

| Result | Decision |
|---|---|
| `idevice` works | Use it |
| `idevice` fails on one OS | Write our own minimal usbmux client: plist `Connect` messages over the socket, about 300 lines |
| USB slower than Wi‑Fi | USB stays as a fallback for networks without client-to-client traffic (guest Wi‑Fi), not as the fast path |

---

## Summary: what each result flips

| Spike | Decision it controls | Default if the spike is skipped |
|---|---|---|
| R1 | Exporter count; in-memory path for small photos | 2 photo + 1 video exporters, spool only |
| R2 | One vs two connections; DATA chunk size | One connection, 256 KiB |
| R3 | §2.5 resource table; O3 burst resolution; O6 KVC sizes | Send all non-proxy; expand bursts by identifier; re-export `have` assets for VERIFY |
| R4 | Delete batch size | 2,000 per batch |
| R5 | Ship experimental background mode or not | Foreground only |
| R6 | Look-ahead depth; phone `max_unacked_bytes` | Look-ahead 1, budget `min(2 GB, 10%)` |
| R7 | Install path | iloader direct install weekly |
| R8 | usbmux client implementation | Own minimal client |
| R9 | Fingerprint shortcut; extra modified guard; metadata sidecars | Always recompute fingerprint; sidecars on move |
| R10 | Resource-list cache; page size | No cache; 500 per page |

The "skipped" defaults are the safe choices, so M3+ can proceed even if a spike can't be run.
