# IOStransfer — Receiver Writer-Path Test Oracle (draft 0.1)

Expected behaviour of the PC receiver's write path (PROTOCOL §6.1–§6.4, §9, §10), written so each case maps
1:1 onto a Rust integration test. Every case lists:

- **Script**: the frames the phone simulator sends (S) and expects (R).
- **Crash**: the crash point, if any.
- **Disk**: the expected on-disk state, before and after restart.
- **DB**: the expected rows.
- **After**: the expected NEED/ACK after restart.

---

## 1. Conventions

### 1.1 Parameters (test config, not the production defaults)

| Symbol | Meaning | Test value | Production |
|---|---|---|---|
| `C` | checkpoint interval (fsync `.part` + commit `durable_offset`) | 64 KiB | 64 MiB |
| `K` | DATA chunk size the simulator sends | 16 KiB (`C/4`) | 256 KiB |
| `RES` | free-space reserve before RES_BEGIN | 1 MiB | 1 GiB |
| `FREEPOLL` | free-space re-check while `PAUSE{disk_low}` | 100 ms | 5 s |

**Checkpoint rule.** After appending a DATA chunk, if `written ≥ durable_offset + C`, then:
1. flush the BufWriter,
2. `fsync(.part)`,
3. commit `durable_offset = written`.

With `K | C` this lands exactly on multiples of `C`. **Session end with the process alive** (BYE, disconnect,
supersede, RES_ABORT of a resumable kind) does the same with `durable_offset = written`, regardless of `C`.

### 1.2 Fixtures

`gen(seed, n)` produces deterministic content: byte `i` = `(seed·7 + i·31) mod 251`. Hashes are computed by the test.

Device `D` = `0b7c1c1e-3f7a-4c8e-9a51-2a3b4c5d6e7f`, name "Test iPhone" (provisioned with `--dev-device`).
All assets have `created_ms = 1710411322000` (2024-03-14T10:15:22Z) and `tz_min = 60`, so the local time is
`20240314_111522` unless a case says otherwise.

| Asset | Resources (key: uti, original name, content) |
|---|---|
| **P** (photo) | `photo#0`: public.heic, IMG_0001.HEIC, `gen(1, 4C+100)` |
| **L** (Live) | `photo#0`: public.heic, IMG_0002.HEIC, `gen(2, 2C)`; `paired_video#0`: com.apple.quicktime-movie, IMG_0002.MOV, `gen(3, 3C+7)` |
| **E** (edited) | `photo#0`: IMG_0003.HEIC `gen(4, C)`; `full_size_photo#0`: public.heic, FullSizeRender.HEIC `gen(5, C+1)`; `adjustment_data#0`: com.apple.photos.adjustment, IMG_0003.AAE `gen(6, 500)` |
| **V** (video) | `video#0`: com.apple.quicktime-movie, IMG_0004.MOV, `gen(7, 6C)` |
| **B** (collides with **P**) | `photo#0`: public.heic, **img_0001.heic**, `gen(8, 2C)`; `paired_video#0`: IMG_0001.MOV `gen(9, C)`; same `created_ms` and `tz_min` as **P** |

Expected paths (`<dev>` = `<dest>/Test iPhone`):

```
P  photo#0            <dev>/Photos/2024/03/20240314_111522_IMG_0001.HEIC
L  photo#0            <dev>/Photos/2024/03/20240314_111522_IMG_0002.HEIC
L  paired_video#0     <dev>/Photos/2024/03/20240314_111522_IMG_0002.MOV
E  photo#0            <dev>/Photos/2024/03/20240314_111522_IMG_0003.HEIC
E  full_size_photo#0  <dev>/Photos/2024/03/20240314_111522_IMG_0003_edited.HEIC
E  adjustment_data#0  <dev>/Photos/2024/03/20240314_111522_IMG_0003.AAE
V  video#0            <dev>/Videos/2024/03/20240314_111522_IMG_0004.MOV
B  photo#0            <dev>/Photos/2024/03/20240314_111522_img_0001_2.HEIC   (§N7)
B  paired_video#0     <dev>/Photos/2024/03/20240314_111522_img_0001_2.MOV
move-job sidecar      <same dir>/<base>.xmp
.part of any final    <dir>/.<final name>.part
```

### 1.3 DB columns the oracle refers to

Names are a proposal; rename freely, but keep the meaning.

```
assets    (device_id, asset_id, base_rel, modified_ms, meta_json, xmp_meta_hash NULL, state)
resources (device_id, asset_id, res_key, rel_path, size, durable_offset, sha256 NULL,
           state ∈ {partial, verified, done, orphaned})
```

- `base_rel` is allocated once per asset, at the asset's first RES_BEGIN, and **committed before** any `.part`
  is created.
- A `resources` row is created **and committed** at RES_BEGIN, with `state = partial` and `durable_offset = 0`.

### 1.4 Script notation

```
S: MANIFEST copy p0 [P]                    job mode copy|move, page 0, assets…
R: NEED p0 want{P:[photo#0@0]} have{}
S: SEND P.photo#0 s0 from 0               = RES_BEGIN{slot 0, offset 0, size} + DATA chunks of K + RES_END{size, sha256}
S: SEND… upto X                           = RES_BEGIN + DATA up to byte X, no RES_END
S: ASSET_END P [photo#0] complete
R: ACK P durable
```

### 1.5 Harness

1. Each case starts with an empty `<dest>` and an empty config dir.
2. The receiver runs as a **child process**:
   `iostransfer receive --insecure-dev --dev-device D:<hex> --dest <tmp> --checkpoint-bytes C --reserve-bytes RES`.
3. The phone simulator is in-test Rust: a TCP client that does the preface, the secret handshake, and then the script.
4. **Crash** = `IOST_CRASH_AT=<point>[:<arg>]` in the child's environment. The receiver calls
   `std::process::abort()` at that point: no destructors and no BufWriter flush. The test waits for the child to
   exit by signal, inspects disk and DB (opened read-only), then restarts the child **without** the variable.
   Startup recovery (PROTOCOL §10) runs before the listener accepts.
5. **Limitation:** `abort()` keeps the OS page cache. Bytes written but not fsynced survive, unlike real power loss.
   So the oracle states `.part` length as a **range** before restart and as an **exact** value after recovery,
   which truncates to `durable_offset`. Power-loss fidelity is out of scope for CI.

### 1.6 Crash points (`IOST_CRASH_AT`)

| Point | Fires | Arg |
|---|---|---|
| `P1:<n>` | after the DATA chunk that makes `written ≥ n` is appended (BufWriter, not flushed) | byte count |
| `P2` | after the RES_END hash and size check passed, **before** the final `fsync(.part)` | — |
| `P3` | after `state = verified` is committed, **before** rename | — |
| `P4` | after rename, **before** the dir fsync and the `done` commit | — |
| `P5` | after the asset's last `done` commit, **before** ACK is sent | — |
| `X1` | after `<base>.xmp.tmp` is written and fsynced, **before** the rename | — |
| `R1` | during startup recovery, after renaming a `verified` row's `.part`, **before** its `done` commit | — |

Add `IOST_CRASH_KEY=<res_key>` to fire only for that resource, and `IOST_CRASH_NTH=<k>` to fire on the k-th hit.

### 1.7 Invariants checked after EVERY case

- **I-A:** No `ACK durable` was ever sent for an asset unless every key in its last `ASSET_END` is `done`, its final
  file exists with the row's size and sha256, and (in a move job) `<base>.xmp` matches `meta_json`.
- **I-B:** No `.part` or `.xmp.tmp` without a `partial` or `verified` row remains after startup recovery.
- **I-C:** For every `done` row, sha256(file) = row sha256. The test re-hashes.
- **I-D:** No file outside `<dest>` is created or modified. Check by snapshotting the parent dir.
- **I-E:** Re-running startup recovery on the final state is a no-op (idempotence).

---

## 2. Baseline (no crash)

### W1 — single photo
```
S: MANIFEST copy p0 [P]      R: NEED want{P:[photo#0@0]}
S: SEND P.photo#0 s0 from 0  S: ASSET_END P [photo#0] complete
R: ACK P durable
```
- **Disk:** the final file exists, size 4C+100, correct hash; no `.part`.
- **DB:** the P row is `done`, `durable_offset` = 4C+100.
- **During the transfer** (assert after 2C bytes, before RES_END): `.part` exists and `durable_offset = 2C` (checkpoint rule).

### W2 — Live photo, ACK only after ASSET_END
```
S: MANIFEST copy p0 [L]      R: NEED want{L:[photo#0@0, paired_video#0@0]}
S: SEND L.photo#0 s0         (assert: no ACK within 300 ms)
S: SEND L.paired_video#0 s0  (assert: no ACK within 300 ms)
S: ASSET_END L [photo#0, paired_video#0] complete
R: ACK L durable
```
- **Disk:** both finals exist and share the base `20240314_111522_IMG_0002`.

### W3 — interleaved slots
```
S: MANIFEST copy p0 [P, V]   R: NEED want{P:[photo#0@0], V:[video#0@0]}
S: RES_BEGIN s0 P.photo#0; RES_BEGIN s1 V.video#0; DATA alternating s0/s1 per chunk; RES_END s1; RES_END s0
S: ASSET_END V …; ASSET_END P …   R: ACK V durable, ACK P durable (in that order)
```
- **Disk:** V is under `Videos/`, P under `Photos/`. Both hashes are correct.

### W4 — re-sent `have` asset (second session)
After W1, disconnect, then a new session:
```
S: MANIFEST copy p0 [P]   R: NEED want{} have{P}
```
- **Disk:** P's final file has the same inode and mtime as before (no rewrite), and no `.part` exists.
- **Also:** `RES_BEGIN` for P.photo#0 now → `BYE protocol_error` (key not wanted).

### W5 — resume where `offset == size`
Run P2 below with a resource whose size is an exact multiple of `C`: **L.photo#0** (2C).
After restart: `NEED want{L:[photo#0@2C, paired_video#0@0]}`.
```
S: RES_BEGIN s0 L.photo#0 offset=2C size=2C; (no DATA); RES_END{size 2C, sha256}
```
- **Disk:** the receiver hashes the `.part` prefix from disk, finds it equal, and the row becomes `done`. No NACK.

---

## 3. Crash cases (PROTOCOL §10)

### P1a — mid-DATA after two checkpoints (crash matrix P1)
```
S: MANIFEST copy p0 [P]   R: NEED want{P:[photo#0@0]}
S: SEND… P.photo#0 upto 2C+5000          crash: P1:2C+5000
```
- **Disk before restart:** `.part` length ∈ [2C, 2C+5000+K].
- **DB:** partial, `durable_offset = 2C`.
- **After recovery:** `.part` length is **exactly 2C**.
- **After reconnect:** `S: MANIFEST copy p0 [P]` → `R: NEED want{P:[photo#0@2C]}`.
  The simulator sends from 2C → `ACK durable`. The final hash equals `gen(1, 4C+100)`.

### P1b — before the first checkpoint
Crash `P1:C-1`.
- **DB:** partial, `durable_offset = 0`.
- **After recovery:** `.part` exists with length **0**.
- **After:** `NEED want{P:[photo#0@0]}`.

### P1c — Live photo, second resource mid-flight
`SEND L.photo#0` completes; `SEND… L.paired_video#0 upto C+K`; crash `P1:C+K` with `IOST_CRASH_KEY=paired_video#0`.
- **DB:** `photo#0` is `done`, `paired_video#0` is partial with `durable_offset = C`.
- **After:** `NEED want{L:[paired_video#0@C]}`, so `photo#0` is **not** wanted. After the resume and ASSET_END → ACK L durable.

### P2 — hash ok, crash before the final fsync (crash matrix P2)
`SEND P.photo#0` fully; crash `P2`.
- **DB:** partial, `durable_offset = 4C` (last checkpoint; 4C+100 is not a multiple).
- **After recovery:** `.part` is exactly 4C.
- **After:** `NEED want{P:[photo#0@4C]}` → resume → done.

### P3 — verified, crash before rename (crash matrix P3)
`SEND P.photo#0`; crash `P3`.
- **Disk before restart:** `.part` is complete (4C+100); there's no final file.
- **DB:** `verified`, sha256 set.
- **After recovery:** `.part` is gone and the final file exists with the correct hash. **DB:** `done`.
- **After:** `NEED have{P}`. No ACK is expected for P in this session, because it isn't in `want`.

### P3-R1 — crash again during recovery (idempotence)
Crash `P3`, restart with `IOST_CRASH_AT=R1`, restart again with no crash.
- **Final:** same as P3. Recovery handles "verified, .part absent, final present, size matches" → `done`.

### P4 — renamed, crash before the done commit (crash matrix P4)
`SEND P.photo#0`; crash `P4`.
- **Disk:** the final file exists and there's no `.part`. **DB:** `verified`.
- **After recovery:** `done`. **After:** `NEED have{P}`.

### P4b — final file damaged between crash and restart
Same as P4, but before the restart the test truncates the final file to 10 bytes.
- **After recovery:** the row is reset to partial with `durable_offset = 0`. **The damaged final file is NOT deleted
  by recovery.**
- **After:** `NEED want{P:[photo#0@0]}`. After the transfer the final is atomically replaced and the hash is correct.

### P5 — done, crash before ACK (crash matrix P5)
Live **L**: both resources sent, `ASSET_END`; crash `P5`.
- **DB:** both rows `done`.
- **After:** `NEED have{L}`. That's the phone's ACK substitute (crash matrix P5 / S3).

### X1 — move job, crash during the XMP write
```
S: MANIFEST move p0 [P with meta {fav:true, loc:{lat:48.8583701, lon:2.2944813}}]
S: SEND P.photo#0; ASSET_END P   crash: X1
```
- **Disk before restart:** `<base>.xmp.tmp` exists; there's no `<base>.xmp`. The photo row is `done`.
- **After recovery:** `.xmp.tmp` is deleted. `xmp_meta_hash` is NULL.
- **After:** the same `MANIFEST move` → the receiver writes `<base>.xmp` durably **before** sending NEED, then
  `NEED have{P}`. The XMP contains `xmp:Rating=5` and GPS 48.8583701 / 2.2944813. `xmp_meta_hash` is set.

### OR — orphan `.part` with no row
Before the start, create `<dev>/Photos/2024/03/.stray.part` with no DB row.
- **After recovery:** it's deleted. Files without a leading dot and `.part` suffix are never touched.

---

## 4. Error paths (no crash)

### N1 — hash mismatch → NACK, retry from 0
```
S: RES_BEGIN s0 P.photo#0 off 0; DATA…; RES_END{size ok, sha256 = zeros}
R: RES_NACK {id P, key photo#0, why hash_mismatch, attempt 1}
```
- **Disk:** `.part` is deleted. **DB:** partial, `durable_offset = 0`, `rel_path` **unchanged**.
- **Retry:** the simulator sends correctly from 0 → `done`. Three bad attempts give `attempt` 1, 2, 3; the
  receiver doesn't enforce the limit (the sender does), it only counts.

### N2 — size mismatches
- (a) `RES_END.size ≠ RES_BEGIN.size` → `RES_NACK size_mismatch`.
- (b) RES_END after fewer bytes than `size` → `RES_NACK size_mismatch`.
- (c) A DATA frame would pass `size` → `RES_NACK bad_offset`. Later DATA on that slot is discarded until the next
  RES_BEGIN, and the connection stays up.
- **Disk/DB** in all three: as N1.

### N3 — offset errors
- (a) DATA with offset ≠ expected (skip one chunk) → `RES_NACK bad_offset`; then as N2c.
- (b) After P1a recovery, `RES_BEGIN offset=C` while NEED said 2C → `RES_NACK bad_offset`.
- (c) After P1a recovery, `RES_BEGIN offset=0` → accepted. `.part` is truncated to 0 and the transfer completes.

### N4 — RES_ABORT kinds
Send P.photo#0 up to 2C+K, then RES_ABORT.

| why | Disk | DB | ASSET_END then |
|---|---|---|---|
| `not_local`, `asset_gone` | `.part` deleted | resource row deleted; asset `base_rel` kept | `ASSET_END{complete:false, why}` → `ACK failed` |
| `cancelled`, `read_error`, `spool_space` | `.part` = 2C+K exactly (fsynced at abort) | partial, `durable_offset = 2C+K` | `ACK failed`; next session `NEED want{P:[photo#0@2C+K]}` |

### N5 — edit changed: NEED_MORE
Setup: E transferred fully (copy) in session 1 with `modified_ms = M1`. Session 2 sends E with `modified_ms = M2`, the
same render size hint (C+1), and an AAE of `gen(16, 500)`, whose hash differs.
```
S: MANIFEST copy p0 [E(M2)]   R: NEED want{E:[adjustment_data#0@0]}      (photo#0: original family → have;
                                                                          full_size_photo#0: same size → provisional have)
S: SEND E.adjustment_data#0
R: NEED_MORE {E, [full_size_photo#0@0]}
S: ASSET_END E [photo#0, full_size_photo#0, adjustment_data#0] complete   (assert: no ACK, NEED_MORE outstanding)
S: SEND E.full_size_photo#0 (new content gen(15, C+1))
S: ASSET_END E [...] complete
R: ACK E durable
```
- **Disk:** `_edited.HEIC` has the new hash at the **same path**, and the `.AAE` is new. `photo#0` is untouched
  (same inode). While the new render was mid-transfer (after its first chunk), the old `_edited.HEIC` was
  still present with the old hash. That's the atomic-replace check.
- **DB:** `assets.modified_ms = M2`.

**N5b:** same, but the AAE is unchanged → no NEED_MORE, and `ACK durable` right after ASSET_END.
**N5c:** `M2`, render size hint C+2 → `NEED want{E:[adjustment_data#0@0, full_size_photo#0@0]}` directly.

### N6 — unchanged `modified_ms`
E re-manifested with M1 → `NEED have{E}` (all done, same modified). No resources are requested.

### N7 — name collisions
- (a) After P is done (copy), send **B**. Then:
  - **Disk:** `…_img_0001_2.HEIC` and `…_img_0001_2.MOV` (the case-insensitive match against `IMG_0001` gives
    suffix `_2`, **shared** by both of B's resources).
  - **DB:** `base_rel` = `…_img_0001_2`.
- (b) **Concurrent:** P and B in one MANIFEST, with `RES_BEGIN s0 B.photo#0` sent **before** `RES_BEGIN s1 P.photo#0`.
  Then **B** gets the unsuffixed base (`…_img_0001`) and **P** gets `…_IMG_0001_2`. The first RES_BEGIN wins,
  deterministically.
- (c) **Pre-existing user file:** before the start, the test creates `<dev>/Photos/2024/03/20240314_111522_IMG_0001.HEIC`
  containing "user data" and not in the DB. Sending P gives `…_IMG_0001_2.HEIC`. The user's file is unchanged
  (content and mtime).
- (d) **Stability:** after (a), a new session with B → `NEED have{B}`, and the paths are unchanged.

### N8 — orphaning (edit reverted)
E done. Then MANIFEST with E: `modified_ms = M3`, resources = only `photo#0`.
- **After:** `NEED have{E}`.
- **DB:** `full_size_photo#0` and `adjustment_data#0` rows are `orphaned`.
- **Disk:** the `_edited.HEIC` and `.AAE` files **still exist**, unchanged.

### N9 — disk low → PAUSE / RESUME
The test's free-space hook returns `RES + 10` bytes.
```
S: MANIFEST copy p0 [P]  R: NEED want{P:[photo#0@0]}
S: RES_BEGIN s0 P.photo#0 size 4C+100
R: RES_NACK {P, photo#0, disk_full, attempt 1};  R: PAUSE {disk_low}
```
- **Disk:** no `.part` was created (the check happens before create).
- **Recovery:** the test raises free space to 1 GiB → within `FREEPOLL`+50 ms, `R: RESUME`. The simulator resends
  from 0 → done.
- **Also:** while PAUSEd, the receiver keeps answering PING and its own peer-dead timer still runs normally,
  because it's still reading. Δ15 applies only to writer backpressure, which N12 covers.

### N10 — superseding session while the old writer holds a `.part`
```
session S1: MANIFEST copy p0 [P]; NEED; SEND… P.photo#0 upto 2C+3K (no checkpoint since 2C)
session S2 (same device D) connects and completes the handshake
R→S1: BYE {superseded}; S1 closed
```
- **Before S2's WELCOME arrives at the simulator:** S1's writer has flushed and fsynced. The DB shows partial with
  `durable_offset = 2C+3K` (**exact**, not checkpoint-rounded, because the process is alive).
- **After:** S2 `MANIFEST copy p0 [P]` → `NEED want{P:[photo#0@2C+3K]}`. DATA still in flight on S1 after the
  supersede is never written. Check: the final hash is correct after S2 completes.

### N11 — phone disconnects mid-resource (no BYE)
Same as N10 without S2. After the socket closes, the DB shows `durable_offset = written` (exact).
The next session resumes there.

### N12 — writer backpressure doesn't kill the session (Δ15)
Test hook: `--test-slow-writer-ms 40000` makes the writer stall 40 s on the first checkpoint fsync.
The simulator keeps sending DATA until its socket blocks, sends nothing for 35 s, and keeps reading.
- **Expected:**
  - the receiver doesn't BYE `timeout`;
  - the simulator receives receiver PINGs (≤ every 10 s);
  - after > 20 s blocked, `R: PAUSE{disk_slow}`;
  - after the stall ends, `R: RESUME` and the transfer completes.

### N13 — protocol violations in the ready phase → `BYE protocol_error`
Each sub-case leaves the DB unchanged, except for rows already committed:
- (a) RES_BEGIN for a key not in `want` or `NEED_MORE`.
- (b) RES_BEGIN on a busy slot.
- (c) DATA on a free slot.
- (d) slot ≥ `max_slots`.
- (e) NEED-less page: MANIFEST p1 before p0 was answered **and** 2 pages are already outstanding (3rd page).
- (f) the same asset in two pages of a copy job.

### N14 — ASSET_END lists a key that isn't done
P manifested with `[photo#0]`. The simulator sends `ASSET_END P [photo#0, paired_video#0] complete` without sending
`photo#0` → `R: ACK P failed [{photo#0, missing}, {paired_video#0, missing}]`.

### N15 — final file deleted by the user
After W1, the test deletes the final file. New session, same MANIFEST → `NEED want{P:[photo#0@0]}`. The row is
reset; after the transfer, the file is back at the **same** `rel_path`.

### N17 — one receiver per destination
While a receiver runs on `<dest>`, start a second `iostransfer receive --dest <dest>` on another port. It MUST
exit non-zero within **1 s** with "another iostransfer is already using <dest>": `locking_mode=EXCLUSIVE`
plus `busy_timeout(0)`. rusqlite's default 5 s busy timeout would make it hang. No `index.db-shm` file
exists at any point.

### N16 — meta refresh on a `have` asset (move job)
After X1's successful end, MANIFEST move with P meta `fav:false`, no location.
- **Before NEED arrives:** `<base>.xmp` is rewritten (Rating removed, no GPS).
- **Then:** `NEED have{P}`. No resource rows changed.

---

## 5. VERIFY (move safety) — the receiver half of PROTOCOL §6.4

Precondition: X1's end state (P done, XMP current), unless stated.

| Case | VERIFY content for P | Expected |
|---|---|---|
| V1 | `res:[photo#0 size 4C+100]`, meta as stored | `ok:[P]` |
| V2 | `res:[photo#0, paired_video#0 size 10]` (a key the PC never had) | `bad:[{P, missing_resource, paired_video#0}]` |
| V3 | `photo#0 size 4C+99` | `bad size_mismatch` |
| V4 | test deletes the final file first | `bad file_missing` |
| V5 | E with `adjustment_data#0 sha256` ≠ stored | `bad hash_mismatch` |
| V6 | meta `fav:false` (differs) | XMP rewritten durably first, then `ok:[P]` |
| V7 | unknown asset id | `bad unknown_asset` |
| V8 | `--paranoid`, test flips one byte in the final file (same size) | `bad hash_mismatch` |
| V9 | 1,001 assets in one VERIFY | `BYE protocol_error` (limit 1,000 per frame) |

---

## 6. Mapping to milestones

- **M1 (writer lands):** W1–W5, P1a–P5, P3-R1, P4b, OR, N1–N4, N7, N10, N11, N13–N15, N17.
- **With NEED_MORE / meta:** N5, N6, N8, N16, X1.
- **With PAUSE and the slow-writer hook:** N9, N12.
- **With VERIFY:** V1–V9.
- **CI:** every case on Linux; on Windows, run W1, P1a, P3, P4, N7c and N10. That covers `MoveFileExW` write-through
  replace, case-insensitive names on NTFS, and `.part` handling on Windows.
