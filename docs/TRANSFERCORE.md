# IOStransfer — TransferCore (Swift) Specification (draft 0.2)

TransferCore is the phone-side engine: framing, the sender session, scheduling, the journal and the move
decisions. It builds and tests on **Linux** (`swift test`) and is driven by two thin hosts: the iOS **App** and
the Linux **InteropSender**. This document defines its API and behaviour. Wire behaviour is normative in
PROTOCOL.md, and section references (§) point there unless noted.

---

## 1. Design rule: sans-I/O core

The core does **no I/O and no waiting**. It is a deterministic state machine:

```
             Event (with `now`)                         [Action]
 Driver ───────────────────────────►  SenderCore  ───────────────────────────► Driver
 (App / InteropSender / tests)      handle(_:) -> [Action]     (performs I/O, later feeds results back as Events)
```

- Every input is an `Event`, every side effect is an `Action`. `handle(_:)` is synchronous, non-blocking and
  O(work in the event), with no loops over the whole library.
- Time is an input. Each event carries `now: Now` (monotonic + wall ms). The core never reads a clock or
  sleeps. Timers use `now.mono`; **anything persisted** (`job.created_ms`, `verified_at_ms`,
  `delete_batch.created_ms`) uses `now.wallMs`. A monotonic value in the journal would be meaningless after a
  reboot, and could even lie in the "future" of the new clock.
- Randomness (nonces) comes from an injected `RandomSource`.
- The only synchronous dependency is the **journal** (local SQLite), behind the `JournalStore` protocol, with an
  in-memory implementation for tests.
- Why this design: the same core runs on iOS (Network.framework, PhotoKit), on Linux (POSIX sockets, files) and in
  simulation tests with a fake clock, fake receiver and injected crashes, with no mocks of async APIs.

The driver serialises all calls. On iOS that's one `actor SessionDriver`; the core itself is a non-`Sendable`
`final class` owned by that actor.

---

## 2. Package layout

```
ios/TransferCore/  (Swift Package, swift-tools 5.10, platforms: iOS 16, Linux)
  Sources/
    IOSTWire/       Frame codec, preface, message Codable types, DATA chunk, error types
    IOSTCrypto/     SHA-256 streaming hasher, HMAC proofs, SPKI pin, pairing code, fingerprint   (swift-crypto)
    IOSTCore/       SenderCore, Scheduler, AssetPipeline, MoveCoordinator, Progress, Backoff
    IOSTJournal/    JournalStore protocol, SQLiteJournal (system libsqlite3), InMemoryJournal
    IOSTSelection/  SelectionRule model, RangeMath over an abstract AssetIndex (no PhotoKit)
  Tests/
    IOSTWireTests/      loads ../../../testdata/protocol-vectors.json (frames, streams, decode_errors)
    IOSTCryptoTests/    hmac, spki, pairing_code, fingerprint vectors
    IOSTCoreTests/      scripted-receiver tests + SimHarness property tests (§9)
    IOSTSelectionTests/
```

Dependencies: `swift-crypto` (exact pinned version) and nothing else. JSON uses Foundation `JSONEncoder` /
`JSONDecoder` with explicit `CodingKeys` matching PROTOCOL field names. Optional fields are encoded by omission
(`encodeIfPresent`), never as `null`.

**Wire strictness (vectors `control_bom`, `control_invalid_utf8`):** before calling `JSONDecoder`, the codec
MUST reject a payload that starts with `EF BB BF` or that isn't valid UTF-8
(`String(validating:as: UTF8.self)` / a manual check). Foundation is lenient about both.

---

## 3. Domain types

```swift
public typealias AssetID = String            // PHAsset.localIdentifier (opaque, may contain "/")
public typealias ResKey  = String            // "<type>#<n>", §5.1
public typealias MonoMs  = UInt64            // monotonic milliseconds, supplied by the driver
public struct Now {                          // every event carries both clocks
    public var mono: MonoMs                  // ContinuousClock: timers only, NEVER persisted (resets at boot)
    public var wallMs: Int64                 // Date(): the ONLY clock written to the journal
}

public enum Section: String, Codable { case photos, videos }
public enum JobMode: String, Codable { case copy, move }
public enum Lane: Hashable { case photo, video }

public struct AssetMeta: Codable, Equatable {        // §5.2, Δ18
    public var createdMs: Int64
    public var tzMin: Int32                          // per asset (Δ6)
    public var fav: Bool
    public var loc: Location?                        // lat, lon, alt?
}

public struct ResourceDescriptor: Codable, Equatable {
    public var key: ResKey
    public var type: String                          // §5.1 type string
    public var uti: String
    public var name: String                          // originalFilename
    public var sizeHint: UInt64?                     // KVC fileSize, best effort
    public var family: ResourceFamily { … }          // derived from `type`, §5.1
}

public struct AssetDescriptor: Codable, Equatable {  // what the driver loads per asset
    public var id: AssetID
    public var kind: Section
    public var meta: AssetMeta
    public var modifiedMs: Int64
    public var w: Int, h: Int, durMs: Int64?
    public var burstID: String?
    public var subtypes: [String]
    public var resources: [ResourceDescriptor]       // already without photo_proxy
}

public struct SpoolRef: Hashable {                   // core-chosen location, driver-owned storage
    public var jobID: UUID
    public var assetDir: String                      // lowercase hex sha256(AssetID), §8.2
    public var key: ResKey
}

public struct Credentials {
    public var deviceID: UUID
    public var deviceName: String
    public enum Auth { case pair(token: String), secret(Data) }   // secret: 32 bytes
    public var auth: Auth
    public var expectedPCID: UUID?                   // nil only while pairing
}

public struct JobSpec: Codable {
    public var jobID: UUID
    public var mode: JobMode
    public var section: Section
    public var label: String
    public var rulesJSON: Data                       // opaque to the core (stored in the journal)
}
```

---

## 4. Events (driver → core)

```swift
public enum Event {
    // lifecycle
    case startJob(JobSpec, now: Now)
    case cancelJob(now: Now)                              // user stop; resumable
    case tick(now: Now)                                   // driver calls ≥ 1 Hz while a job is active

    // transport
    case transportUp(isTLS: Bool, now: Now)               // after TCP + TLS (pin already checked by the driver)
    case received(Data, now: Now)                         // any chunking; the core reassembles frames
    case sendCompleted(token: UInt64, now: Now)           // the driver's write for that Action finished
    case transportDown(reason: TransportDownReason, now: Now)
    case secretStored(now: Now)                           // Keychain write for .storeSecret succeeded

    // asset source (the driver paginates its resolver: lazy, ordered, de-duplicated)
    case assetsLoaded([AssetDescriptor], exhausted: Bool, now: Now)

    // export into the spool (writeData + .tmp→rename done by the driver)
    case exported(SpoolRef, size: UInt64, now: Now)
    case exportFailed(SpoolRef, ExportFailure, now: Now)  // notLocal | readError | noSpace | assetGone

    // spool reads
    case readDone(token: UInt64, Data, now: Now)          // ≤ requested length; empty = EOF
    case readFailed(token: UInt64, now: Now)

    // move phase (PhotoKit work done by the driver)
    case currentState([AssetCurrentState], now: Now)      // answer to .inspectAssets
    case deleteFinished(batchID: UUID, DeleteOutcome, now: Now) // success | userCancelled | error(String)

    // environment
    case freeSpaceChanged(bytes: UInt64, now: Now)
    case thermal(ThermalLevel, now: Now)                  // nominal | fair | serious | critical
}

public struct AssetCurrentState {                            // driver's fresh look at one asset
    public var id: AssetID
    public var exists: Bool
    public var canDelete: Bool                               // canPerform(.delete) && sourceType == .typeUserLibrary
    public var isLocal: Bool
    public var modifiedMs: Int64
    public var fingerprint: FingerprintInput?                // present iff the core asked for it (§7)
}

public struct FingerprintInput {                             // §6.4 canonical-form inputs
    public var meta: AssetMeta
    public var resources: [(key: ResKey, size: UInt64)]
    public var adjustmentSHA256: [ResKey: Data]              // for every adjustment_data key
}
```

---

## 5. Actions (core → driver)

```swift
public enum Action {
    // transport
    case connect(attempt: Int)                     // Wi‑Fi: driver dials (Bonjour/QR addresses, 5 s each)
    case send(Data, token: UInt64)                 // fully encoded frames; driver reports .sendCompleted
    case closeTransport(after: Data?)              // optional final bytes (BYE), then close within 2 s
    case storeSecret(Data, pcID: UUID, pcName: String, pin: Data?) // pairing: persist, then .secretStored

    // asset source
    case beginAssetSource(skip: Set<AssetID>)      // once per connection: journal-acked IDs to omit (Δ16); empty = none
    case loadAssets(max: Int)                      // next page from the source begun above

    // spool
    case export(AssetID, ResourceDescriptor, to: SpoolRef)
    case read(SpoolRef, offset: UInt64, length: Int, token: UInt64)
    case deleteSpool(jobID: UUID, assetDir: String?) // nil = whole job
    case sweepSpool(keepJob: UUID, dropAssetDirs: Set<String>) // startup: see "spool keep rule" below

    // move phase
    case inspectAssets([AssetID], wantFingerprint: Set<AssetID>)
    case performDelete(batchID: UUID, [AssetID])     // ONE performChanges{deleteAssets}

    // UI
    case progress(JobProgress)                       // ≤ 4 Hz
    case log(LogLevel, String)                       // also forwarded as LOG frames by the core when connected
    case needsUser(UserAction)                       // repair, updateApp(side:), freeSpace(bytes:), pcDiskFull, keepScreenOn
    case jobFinished(JobSummary)
}
```

**Spool keep rule.** The journal persists only terminal-ish states (PROTOCOL §8.3), so "in flight" is not
recorded. The keep set is therefore: every spool file of the **current** job whose asset is **not** in a
terminal state (`acked`, `failed`, `verified`, `deleted`, `declined`, `dropped`). The driver resolves this with
`keep` = the current job's spool dir minus the asset dirs of terminal assets, which the core lists in
`sweepSpool(keepJob: UUID, dropAssetDirs: Set<String>)`. All other jobs' spool dirs and every `.tmp` are deleted.
After a crash this keeps exported-but-unacked files, so resume needs no re-export (crash matrix S2).

Each `token` is unique per core instance. The driver MUST answer every `read` with exactly one `readDone` or
`readFailed`, and every `send` with one `sendCompleted`, unless the transport went down first (then a single
`transportDown` voids all outstanding tokens).

---

## 6. Internal state machines (mapping to PROTOCOL)

### 6.1 Connection (§8.1)

```
idle ─startJob─► connecting ─transportUp─► preface ─► helloSent ─► (challenge ok) ─► authSent ─► ready
                     ▲                                                    └─ pairing: welcome ─► paired ─► ready
                     └──────── backoff (1,2,4,8,16,30,30… s; reset on ready) ◄── transportDown / timeout / retryable BYE
any ─ BYE auth_failed | unknown_device | token_invalid | version_unsupported | disk_full ─► blocked(.needsUser)
```

- On `transportUp` the core sends the preface + HELLO in one `send`.
- `r_proof` is checked in constant time. Mismatch → `closeTransport(BYE auth_failed)` → blocked.
- Pairing: on WELCOME with `device_secret`, the core emits `.storeSecret(secret, pcID:…)`. The driver writes the
  Keychain item, then feeds `.secretStored`, and only then does the core send PAIRED (two-phase, Δ3).
- `expectedPCID` mismatch with WELCOME → close, blocked (`.needsUser(.wrongPC)`).
- Entering `backoff` discards slots, outstanding pages and the unacked set. Only the journal survives (§8.1).

### 6.2 Job pipeline (§6.1–§6.3, §8.2)

```
startJob → journal.createOrResume(job) → sweepSpool(keep: [])       // see "spool keep rule" below
ready    → beginAssetSource(skip: journal.ackedIDs(job, pcID, storeID) ?? [])  // Δ16; nil if store_id changed
         → loadAssets(max: 500) per page
assetsLoaded → MANIFEST(page k)        (≤ 2 pages without NEED)
NEED(k)  → have: mark acked (journal, batched)   want: enqueue in lane by kind, in creation order
Scheduler (§6.3) → export → exported → RES_BEGIN … DATA … RES_END (per resource) → ASSET_END
ACK durable → journal acked; deleteSpool(asset)    ACK failed → journal failed(reason)
RES_NACK → retry from 0 (≤ 3 per resource per job), else ASSET_END{complete:false, retries_exhausted}
NEED_MORE → re-enqueue those keys for the asset, then ASSET_END again
last page NEED'd + nothing in flight + all ACKed → copy: BYE done, jobFinished;  move: §7
```

### 6.3 Scheduler

- Slots: photo lane 3, video lane 1. An idle lane lends its slots. Total slots ≤ `WELCOME.max_slots`.
- **Export look-ahead:** 1 asset per lane beyond the busy slots (R6 may raise it).
- **Window:** `A = max_unacked_assets`, `B = min(max_unacked_bytes, spoolBudget)`, with
  `spoolBudget = min(2 GB, freeSpace / 10)` recomputed on `freeSpaceChanged` (Δ11, Δ17). A resource
  larger than `B` may run alone.
- **Free-space guard:** before `export`, require `sizeHint + 2 GB ≤ freeSpace`, else fail the asset with
  `noSpace` → `.needsUser(.freeSpace(bytes:))`, and continue with others (ARCHITECTURE §2.6).
- **Reads:** 256 KiB per `read`. At most **4 MiB** of `send` bytes outstanding (not yet `sendCompleted`).
  The next read is issued only below that watermark: this is the backpressure (ARCHITECTURE §2.6).
- **Interleave:** round-robin one DATA frame per busy slot. Within an asset, `adjustment_data` goes first.
- **Resume:** if NEED gives `offset > 0`, the core first issues hash-only reads `[0, offset)` (not sent), then
  sends from `offset`. If the spool file is missing it re-exports first (bytes identical for originals; a changed
  edit resource is caught by the hash → NACK → restart from 0).
- **PAUSE:** stop RES_BEGIN/DATA at the next frame boundary; ACK and NEED timers stop (§6.5).
- **Thermal:** `serious` → 1 photo + 1 video slot; `critical` → behave as if PAUSEd (ARCHITECTURE §2.6).

### 6.4 Timers (§7.3), all driven by `tick`/event `now`

Peer-silence 30 s; PING after 10 s of no outbound frames; NEED 60 s; ACK 300 s; VERIFIED 120 s;
handshake 15 s (60 s while pairing); verify freshness 10 min. Expiry → `closeTransport(BYE timeout)` → backoff.

---

## 7. Move coordinator (§6.4, §8.4)

1. When the transfer phase is done, collect `acked` assets in batches of ≤ 1,000. For assets whose fingerprint
   is unknown to the core (the `have`/omitted ones), emit `inspectAssets(ids, wantFingerprint: ids)`.
   The driver returns `FingerprintInput`s, and the core builds VERIFY `res` + `meta` from them.
   For assets sent in this job, sizes come from the spool, and the AAE hash from the hasher.
2. VERIFIED: `ok` → journal `verified(fp, modifiedMs, now)`; `bad` → journal `failed(verify_failed:why)`.
3. Delete batch (after all VERIFY pages, or when the user taps "Delete now"):
   `inspectAssets(okIDs, wantFingerprint: ids whose modifiedMs changed)`. Then for each asset:
   - `!exists` → dropped(gone)
   - `!canDelete` → dropped(not_deletable)
   - `!isLocal` → dropped(not_local)
   - fingerprint ≠ verified_fp → first time: reverify (back to `acked`, re-manifest, Δ re-VERIFY); second time:
     dropped(changed_during_move)
   - verified more than 10 min ago (wall clock), **or verified by a previous core instance** → re-VERIFY first.
     On `createOrResume`, every `verified` row is demoted to `acked` (keeping its fingerprint), so a VERIFY never
     survives a restart. This is cheap, and it removes clock-skew questions entirely.
4. Journal `delete_batch(requested)` + items, then emit `performDelete(batchID, ids)` (≤ 2,000 per batch until R4
   says otherwise).
5. `deleteFinished`: success → `deleted`; userCancelled → `declined` → `.needsUser(.confirmDeleteAgain(n))`; error → `declined`.
6. Restart with a batch in `requested` → `inspectAssets(items)`: missing → `deleted`, present → back to `acked`
   (re-VERIFY, as above; crash matrix S5).
7. **First move to a new PC (N13)** is gated before step 4 by `.needsUser(.confirmFirstMove(pcName))`.

---

## 8. Public API

```swift
public final class SenderCore {
    public init(credentials: Credentials,
                journal: JournalStore,
                random: RandomSource = SystemRandom(),
                config: CoreConfig = .default)            // slots, chunk size, watermarks, timeouts (tests shrink them)

    public func handle(_ event: Event) -> [Action]
    public var snapshot: JobProgress { get }              // for UI polling; same data as .progress
}

public protocol JournalStore {                            // PROTOCOL §8.3 tables
    func createOrResume(_ job: JobSpec, pcID: UUID?, storeID: UUID?) throws -> JobResumeInfo
    func ackedIDs(job: UUID, pcID: UUID, storeID: UUID) throws -> Set<AssetID>?   // nil = binding mismatch → cleared
    func record(_ updates: [JournalUpdate]) throws        // one transaction; the core batches ≤ 1 s
    func pendingDeleteBatches(job: UUID) throws -> [(UUID, [AssetID])]
    func terminalAssetDirs(job: UUID) throws -> Set<String>   // for the spool keep rule
}

public struct JobProgress: Equatable {
    public var phase: Phase                               // connecting | transferring | verifying | deleting | done | blocked
    public var lanes: [Lane: LaneProgress]                // assets done/total, bytes done/known, current rate (EWMA 5 s)
    public var failures: [String: Int]                    // by reason
    public var dropped: [String: Int]                     // by dropped_reason
    public var etaSeconds: Int?
}
```

Journal errors are fatal for the job (`.needsUser(.journalError)`). The core never continues with a journal it
can't write, because the move safety relies on it.

---

## 9. Testing

1. **Vectors:** IOSTWire/IOSTCrypto tests load `testdata/protocol-vectors.json` (path from `#filePath`). They cover
   every frame, stream, decode_error (stage `frame`/`data`/`message`/`preface`), hmac, spki, pairing_code and fingerprint vector.
2. **Scripted receiver:** a test DSL that feeds receiver frames and asserts emitted actions, for example
   `expect(.send(frame: .manifest(page: 0)))`, `feed(.need(...))`. One test per row of the PROTOCOL
   §7.1 BYE table and per §7.3 timeout.
3. **SimHarness (property tests, Linux):** the core plus a **reference receiver model** written in Swift from
   PROTOCOL §6/§9 (in memory: files, durable offsets, crash points). Then random libraries (1–300 assets,
   random resources and sizes, edits mid-job), random network drops, random `ExportFailure`s, random PAUSEs, and
   random **sender crashes**: discard the `SenderCore`, keep the `InMemoryJournal` *as of its last commit*, and build a new core.
   Invariants checked after every step:
   - I1 no `performDelete` for an asset unless the model receiver holds every current resource `done` with
     matching bytes and current meta (the PROTOCOL §10 safety argument as code);
   - I2 every asset in a NEED.want gets exactly one ACK per session (Δ9);
   - I3 unacked window and outstanding-send watermark never exceeded;
   - I4 the job terminates (bounded steps) once the network stays up;
   - I5 the final receiver state = the library (copy) or library ∖ dropped (move).
4. **Interop (CI, ubuntu):** `InteropSender` (the core plus POSIX sockets and a folder `AssetSource` whose
   exporter hard-links into the spool) against the Rust receiver with `--insecure-dev --dev-device <uuid>:<hex64>`.
   Pairing can't run over plaintext by design, so the device is pre-provisioned in memory on the receiver, never
   written to devices.db. Pairing itself is covered by Rust `tls_e2e` and the Swift scripted-receiver tests. Includes the Rust
   `IOST_CRASH_AT=P1..P4` runs (THREAT_MODEL N22) and a kill -9 of InteropSender mid-job.

---

## 10. Driver obligations (summary for App and InteropSender)

| Concern | App (iOS) | InteropSender (Linux) |
|---|---|---|
| Transport | `NWConnection` + TLS 1.3, ALPN, SPKI pin in verify block; pairing code display | POSIX TCP, plain (`--insecure-dev`) |
| AssetSource | SelectionResolver over PhotoKit, 500 per page, `skip` honoured | Sorted folder listing |
| Export | `PHAssetResourceManager.writeData` → `.tmp` → rename; `isNetworkAccessAllowed = false` | Hard link or copy |
| Reads | `FileHandle` at offset on a serial I/O queue | Same |
| Inspect/delete | PHAsset refetch, `canPerform`, KVC sizes, AAE export + hash; `performChanges` | Simulated (dry-run log) |
| Clock | `ContinuousClock` ms; `tick` every 1 s | Same |
| Secrets | Keychain (`AfterFirstUnlockThisDeviceOnly`), runtime-derived service name | `--device <uuid>:<hex64>`, matching the receiver's `--dev-device` (only accepted with `--insecure-dev`) |
| UI | Maps `.progress`, `.needsUser`, `.jobFinished` | Prints them |
