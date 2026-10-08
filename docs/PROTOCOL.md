# IOStransfer — Wire Protocol and State Machines (v1, draft 0.4)

Byte-exact spec for the phone ↔ PC session. Expands ARCHITECTURE §3 (protocol) and §2.8 (move).
Owner: the protocol reviewer. Changes vs ARCHITECTURE §3 are listed in §0 and marked **[Δ]** where they occur.

Key words MUST / MUST NOT / SHOULD / MAY are used in the RFC 2119 sense.

---

## 0. Changes proposed vs ARCHITECTURE §3 (for agreement)

| # | Change | Why |
|---|---|---|
| Δ1 | 8-byte **preface** `IOST\x01\0\0\0` before the first frame | Detects wrong peer / wrong port (USB port scans, stray HTTP) before any JSON parsing. |
| Δ2 | Auth is **HMAC challenge-response** (`CHALLENGE`/`AUTH`), the secret is never sent after pairing | Transport-independent: the same auth works over TLS (Wi‑Fi) and over plain usbmux (USB), and lets the phone authenticate the PC when the PC dials. |
| Δ3 | Pairing is **two-phase** (`WELCOME.device_secret` → phone stores → `PAIRED` → PC commits) | No half-paired state where the PC has a secret the phone lost. |
| Δ4 | `DATA` carries an explicit **u64 offset** | 8 bytes per 256 KiB; every chunk is checkable, and an offset bug is caught at the chunk, not after a 6 GB hash. |
| Δ5 | Version negotiation by range: `HELLO.proto = {min,max}` | Explicit rule, §3. |
| Δ6 | Timestamps are integer **ms since Unix epoch** + **per-asset** `tz_min` (DST-correct, see §5.2); per-resource `size` hint in MANIFEST | Deterministic naming independent of PC timezone; `size` drives the free-space check and the cheap edit-change check. (Modified in draft 0.2 per ARCHITECTURE v0.3.) |
| Δ7 | `collections` **removed** from the per-asset manifest | PhotoKit has no cheap reverse lookup (`fetchAssetCollectionsContaining` per asset is ~100k calls); only the job label is sent. |
| Δ8 | **Resource families** (original = immutable, edit = mutable) + `NEED_MORE` | `modified` changes on favourite/album toggles; this avoids re-sending a 4 GB edited video because of a favourite, while still catching real edits. |
| Δ9 | Every wanted asset gets **exactly one** `ACK` — `ASSET_END{complete:false}` for skipped assets | Simple invariant for both sides; no dangling receiver state. |
| Δ10 | `VERIFY` carries the phone's **current resource key set + sizes** (+ sha256 when known) and `modified_ms`; paged | Assets that were "already on the PC" can be verified without re-exporting/hashing them, and a resource that appeared after the last transfer (new edit) blocks deletion. |
| Δ11 | `max_unacked_assets` / `max_unacked_bytes` in `WELCOME` | The spool is freed on ACK, so spool size is bounded by ACK lag, not only by in-flight slots. |
| Δ12 | Receiver resource states `partial → verified → done` with a **64 MiB fsync checkpoint** | Exact crash recovery for every point in the write path (§9). |
| Δ13 | USB transport security: **plain + Δ2 auth** recommended (vs phone-side TLS identity) | Network.framework cannot be a TLS *client* on an accepted connection, and shipping a PKCS#12 identity to the phone is more moving parts than a cable-local link needs. Decision still belongs to the USB milestone; v1 framing and auth already work either way. |
| Δ14 | Move guard = **content fingerprint** (resource keys + sizes + sha256 of every `adjustment_data`), not exact `modified_ms` (draft 0.2) | `modificationDate` may change from system activity (R9); `modified_ms` is only the trigger to recompute. |
| Δ15 | Receiver **suspends its peer-dead timer** while it deliberately isn't reading (draft 0.2) | Writer backpressure on a slow disk must not make the PC kill a healthy session. |
| Δ16 | Sender **omits** journal-`acked` assets from MANIFEST after a reconnect, keyed by `(pc_id, store_id)`; `WELCOME.store_id` added (draft 0.2) | No 100k `assetResources(for:)` re-scan per Wi‑Fi blip; `store_id` stops omission against a different destination folder. |
| Δ17 | Sender window = `min(WELCOME limits, phone spool budget)` (draft 0.2) | The PC's 2 GiB may exceed the phone's free space. |
| Δ18 | Asset **`meta`** (`created_ms`, `loc`, `fav`) in MANIFEST and VERIFY, part of the fingerprint; PC **always** writes an XMP sidecar on move jobs (copy jobs: only with `--xmp`) (draft 0.3; "always" since 0.4: no EXIF parsing on the PC) | "Adjust Date/Location" and favourites live only in the Photos DB; without this a move loses them (ARCHITECTURE §2.8). |
| Δ19 | QR `spki` = **base64url, no padding** (43 chars) (draft 0.3) | URL-safe inside `iost://` without percent-encoding. |

---

## 1. Transport

| Transport | TCP dialer | TCP listener | Security | Auth |
|---|---|---|---|---|
| Wi‑Fi (v1) | phone | PC (port 47800, Bonjour `_iostransfer._tcp`) | TLS 1.3, PC = TLS server, SPKI pinned | §4 |
| USB (M6) | PC (via usbmuxd) | phone (`NWListener`, port 47801, **bound to loopback only**, only while USB mode is on) | none (Δ13) or TLS (open) | §4 |

### 1.1 TLS profile (Wi‑Fi)

- TLS 1.3 only. ALPN `iost/1` (both sides MUST send it; the server MUST reject other ALPN values).
- PC key: **ECDSA P-256** (rcgen default), generated once, stored in the PC config dir. Self-signed cert, validity 20 years.
- Pin = `SHA-256(SubjectPublicKeyInfo DER)`, carried in the QR as base64url without padding [Δ19]
  (test vector in `testdata/protocol-vectors.json`). For P-256 the SPKI DER is always 91 bytes:
  `3059301306072a8648ce3d020106082a8648ce3d030107034200` (26-byte prefix) ‖ 65-byte uncompressed point.
  On iOS: `SecKeyCopyExternalRepresentation(SecCertificateCopyKey(leaf))` returns exactly the 65-byte point →
  prepend the prefix → SHA-256 → constant-time compare with the QR `spki`. Any other key type MUST fail closed.
- The client MUST NOT send SNI (connecting by IP); the server MUST NOT require it.
- No client certificate.

### 1.2 Preface [Δ1]

Immediately after the transport is ready (after the TLS handshake if TLS is used), **both** sides send 8 bytes:

```
49 4F 53 54  01  00 00 00
 "I  O  S  T" ver  reserved (MUST be 0)
```

Each side MUST receive the peer's preface within **10 s** and MUST close the connection (no BYE) if the
bytes differ. `ver` is the framing version and changes only if the frame header (§2) ever changes.

---

## 2. Framing

```
offset 0      4        5
       ┌──────┬────────┬──────────────────────────┐
       │ len  │ type   │ payload (len − 1 bytes)   │
       └──────┴────────┴──────────────────────────┘
len  = u32 big-endian = 1 + payload length.   1 ≤ len ≤ MAX_FRAME_LEN
type = u8 (§2.2)
```

- `MAX_FRAME_LEN = 1_048_592` (1 MiB + 16). `len = 0` or `len > MAX_FRAME_LEN` → protocol error.
- **Control frames** (every type except `DATA`): payload = one UTF-8 JSON object, no BOM.
  - Receivers MUST ignore unknown JSON fields (forward compatibility inside a protocol version).
  - Integers MUST fit in ±2^53. Byte strings (hashes, nonces, secrets) are **lowercase hex**.
  - Field names are exactly as written below; optional fields are marked `?` and MAY be absent (never `null`).
- **DATA frame** payload (binary) [Δ4]:

```
offset 0        2                10
       ┌────────┬────────────────┬────────────────────────┐
       │ slot   │ offset         │ bytes (1..262144)      │
       │ u16 BE │ u64 BE         │                        │
       └────────┴────────────────┴────────────────────────┘
```

  `offset` = position of the first byte within the resource file. `bytes` MUST be non-empty and ≤ 256 KiB.

Implementation hints: Rust `tokio_util::codec::LengthDelimitedCodec` (u32 BE, `length_adjustment = 0`,
max = MAX_FRAME_LEN) then split off the type byte; iOS `NWProtocolFramer` or a manual reader on `NWConnection.receive`.

### 2.1 Test vectors

The full, machine-readable set (frames, decode failures, preface, HMAC, SPKI pin, fingerprint) is
`testdata/protocol-vectors.json`, generated by `testdata/gen_protocol_vectors.py`. Swift and Rust tests MUST
load that file rather than copying values. Excerpt:

```
PING {"n":1}                     00 00 00 08 70 7b 22 6e 22 3a 31 7d
DATA slot=1 offset=0 "abc"       00 00 00 0e 21 00 01 00 00 00 00 00 00 00 00 61 62 63
sha256("abc")                    ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
HMAC r_proof / s_proof (§4.2) with secret = 01×32, s_nonce = 02×32, r_nonce = 03×32:
  r_proof = 639ea14af8e5f473f64a78507f4e08daf2c817680501d52af35e282652ccfdae
  s_proof = 3d7205c22463caf33a2a0877840489ebc4174c774668d59bcfedd9f3d74d1ea5
```

### 2.2 Frame types

| Type | Name | Dir | Phase |
|---|---|---|---|
| 0x01 | HELLO | S→R | handshake |
| 0x02 | WELCOME | R→S | handshake |
| 0x03 | CHALLENGE | R→S | handshake [Δ2] |
| 0x04 | AUTH | S→R | handshake [Δ2] |
| 0x05 | PAIRED | S→R | handshake [Δ3] |
| 0x10 | MANIFEST | S→R | ready |
| 0x11 | NEED | R→S | ready |
| 0x12 | NEED_MORE | R→S | ready [Δ8] |
| 0x20 | RES_BEGIN | S→R | ready |
| 0x21 | DATA | S→R | ready |
| 0x22 | RES_END | S→R | ready |
| 0x23 | RES_ABORT | S→R | ready |
| 0x24 | ASSET_END | S→R | ready |
| 0x30 | ACK | R→S | ready |
| 0x31 | RES_NACK | R→S | ready |
| 0x40 | VERIFY | S→R | ready |
| 0x41 | VERIFIED | R→S | ready |
| 0x50 | PAUSE | R→S | ready |
| 0x51 | RESUME | R→S | ready |
| 0x60 | LOG | S→R | ready |
| 0x70 | PING | both | any (after preface) |
| 0x71 | PONG | both | any (after preface) |
| 0x7F | BYE | both | any (after preface) |

S = Sender = phone, R = Receiver = PC, regardless of who dialed.
A frame type that is unknown, or known but sent in the wrong direction or phase, is a protocol error (§7).
New frame types are only introduced with a new protocol version (§3).

---

## 3. Version negotiation [Δ5]

- `HELLO.proto = {"min": a, "max": b}` — the sender's supported range. v1 sends `{"min":1,"max":1}`.
- The receiver supports `[c, d]`. If `max(a,c) ≤ min(b,d)` it selects `v = min(b,d)` and returns it in
  `WELCOME.proto` (or in `CHALLENGE.proto`, whichever it sends first). Otherwise it sends
  `BYE{"code":"version_unsupported","min":c,"max":d}` and closes.
- After selection both sides MUST speak exactly version `v`. The preface and frame header (§1.2, §2) and the
  `HELLO`/`BYE`/`PING`/`PONG` frames MUST stay compatible in every future version, so that negotiation always works.
- The app shows "Update the PC app" / "Update the iPhone app" depending on which side is older.

---

## 4. Handshake, pairing and authentication

### 4.1 Pairing session (first contact, TLS transport only)

```
S                                                 R
│ preface ⇄ preface                                │
│ HELLO{auth:{mode:"pair", token}} ───────────────►│ token valid? (one-time, TTL 10 min)
│◄──────── WELCOME{…, device_secret, paired:true} ─│ R holds secret in memory, NOT yet in DB
│ store secret in Keychain                         │
│ PAIRED{} ───────────────────────────────────────►│ R commits devices row (sync), token consumed
│ … session is READY …                             │
```

- **Pairing code (THREAT_MODEL N11):** before sending WELCOME, R shows the code and asks the PC user to approve
  "Pair *device_name*?" (60 s limit, §7.3; declining → `BYE auth_failed`). The phone shows the same code
  after the TLS pin check.
  `code` = the first 40 bits (5 bytes) of the SPKI pin SHA-256, big-endian, split into 8 groups of 5 bits
  (most significant first), each mapped through the Crockford alphabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ`,
  displayed as `XXXX-XXXX`. Vectors: `pairing_code` in `testdata/protocol-vectors.json`.
- `pair` mode over a non-TLS transport MUST be rejected (`BYE auth_failed`).
- If the connection drops before R receives `PAIRED`, R discards the secret; the token stays valid until its
  TTL, so the phone can simply retry. If R crashes after `PAIRED` but before commit, the next secret
  handshake fails with `unknown_device` → the phone shows "Pair again".
- Re-pairing an existing `device_id` replaces its secret.
- Keychain item: `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` (MUST be readable while the screen is
  locked, otherwise background reconnects fail). The `device_id` (UUID v4, generated once) is stored in the
  same Keychain service — not `identifierForVendor`, which changes on reinstall.

### 4.2 Normal session [Δ2]

```
S                                                 R
│ HELLO{auth:{mode:"secret", s_nonce}} ───────────►│ device known?
│◄──────────────── CHALLENGE{proto, r_nonce, r_proof}│
│ verify r_proof (authenticates R)                 │
│ AUTH{s_proof} ──────────────────────────────────►│ verify s_proof (authenticates S)
│◄───────────────────────────────── WELCOME{…} ────│
```

```
s_nonce, r_nonce = 32 random bytes each (hex in JSON)
r_proof = HMAC-SHA256(key = device_secret, msg = "IOST1-R" ‖ s_nonce ‖ r_nonce)
s_proof = HMAC-SHA256(key = device_secret, msg = "IOST1-S" ‖ s_nonce ‖ r_nonce)
("IOST1-R"/"IOST1-S" are 7 ASCII bytes; nonces as raw bytes; compare in constant time)
```

- Unknown `device_id` → `BYE{unknown_device}`. Bad proof on either side → `BYE{auth_failed}` and close.
- R MUST rate-limit failed auths per source address (5 per minute).
- If a session for the same `device_id` is still open, R closes the **old** one with `BYE{superseded}` and MUST
  finish the old session's writer shutdown (§9.3) before it computes any `NEED` for the new one.

### 4.3 Handshake messages

```jsonc
HELLO     { "proto": {"min":1,"max":1}, "device_id": "uuid", "device_name": "Ana's iPhone",
            "app_version": "0.3.0", "os": "iOS 19.1",
            "auth": {"mode":"pair","token":"hex"} | {"mode":"secret","s_nonce":"hex64"} }
CHALLENGE { "proto": 1, "r_nonce": "hex64", "r_proof": "hex64" }
AUTH      { "s_proof": "hex64" }
WELCOME   { "proto": 1, "pc_id": "uuid", "pc_name": "nobara-desktop", "session_id": "uuid",
            "store_id": "uuid",                  // id of <dest>/.iostransfer/index.db (new index ⇒ new id) [Δ16]
            "device_secret"?: "hex64",          // pairing only
            "paired"?: true,                     // pairing only
            "max_slots": 8, "max_unacked_assets": 64, "max_unacked_bytes": 2147483648,
            "free_bytes": 123456789012 }
PAIRED    { }
```

---

## 5. Data model

### 5.1 Resource types and families [Δ8]

`type` strings (from `PHAssetResourceType`):

| type | family | sent |
|---|---|---|
| `photo`, `video`, `audio`, `alternate_photo`, `paired_video` | **original** (immutable) | yes |
| `full_size_photo`, `full_size_video`, `full_size_paired_video`, `adjustment_data`, `adjustment_base_photo`, `adjustment_base_video`, `adjustment_base_paired_video` | **edit** (mutable) | yes |
| `photo_proxy` | — | never |
| `unknown_<rawValue>` | edit (conservative) | yes |

Original-family bytes never change for a given asset (PhotoKit edits are non-destructive), so once `done`
on the PC they are never re-requested. Edit-family resources can change, appear or disappear.

`res_key = "<type>#<n>"`, `n` = 0-based index among resources of the same type, in `assetResources(for:)` order.
Example: `photo#0`, `paired_video#0`, `adjustment_data#0`.

### 5.2 Asset (inside MANIFEST)

```jsonc
{ "id": "6F3A…-…/L0/001",            // PHAsset.localIdentifier (contains '/'! never use raw in paths)
  "kind": "photo" | "video",
  "created_ms": 1710411322000,        // creationDate, ms since epoch UTC
  "tz_min": 60,                       // TimeZone.current.secondsFromGMT(for: creationDate)/60 — per asset,
                                      // DST-correct; travel stays approximate (naming only)
  "modified_ms": 1710411399000,       // modificationDate (hint, not identity)
  "w": 4032, "h": 3024, "dur_ms"?: 12345,
  "fav": false,                       // isFavorite                              } together = asset meta
  "loc"?: {"lat": 48.8583701, "lon": 2.2944813, "alt"?: 35.2},  // PHAsset.location } [Δ18]; created_ms too
  "burst_id"?: "…", "subtypes": ["live","hdr", …],
  "res": [ { "key": "photo#0", "type": "photo", "uti": "public.heic",
             "name": "IMG_4821.HEIC",  // originalFilename
             "size"?: 2481234 } ] }   // best-effort KVC fileSize hint
```

Identity on the PC: `(device_id, id, res_key)`. Names are chosen by the PC once and stored (ARCHITECTURE §4.3).

---

## 6. Ready-phase messages

### 6.1 Job, MANIFEST, NEED

```jsonc
MANIFEST { "job": {"job_id":"uuid","label":"Screenshots","section":"photos"|"videos","mode":"copy"|"move"},
           "page": 0, "last": false, "assets": [Asset, …] }
NEED     { "job_id":"uuid", "page": 0,
           "want": [ {"id":"…","res":[{"key":"photo#0","offset":0}, …]}, … ],
           "have": ["id", …] }
NEED_MORE{ "id":"…", "res":[{"key":"full_size_photo#0","offset":0}, …] }
```

- A page has ≤ 500 assets and its encoded frame MUST fit `MAX_FRAME_LEN`; the sender splits otherwise.
- `page` starts at 0 per job and increments by 1. The sender MUST NOT have more than **2** pages without a NEED.
- Every asset of a page MUST appear in exactly one of `want` / `have` of that page's `NEED`.
- An asset MUST NOT appear in two pages of the same job (the sender de-duplicates), with one exception: in a
  move job, an asset whose fingerprint changed after VERIFY (§8.4 step 1) MAY be manifested **once more** in a
  later page. R handles it like any other asset (meta refresh, edit-family re-request, `have`).
- **Omission [Δ16]:** the sender MAY leave out of every page any asset its journal marks `acked` for this job
  under the same `(pc_id, store_id)` as the current `WELCOME`. If `store_id` differs (PC index recreated or a
  different `--dest`), the sender MUST clear those `acked` marks and manifest everything. In a move job,
  omitted assets still go through VERIFY. The app offers "Re-check everything" to force a full manifest
  (e.g. after the user deleted files on the PC).
- One job per session at a time. A new `job_id` on the same session means the previous job is finished or
  abandoned; R drops in-memory state for the old job (on-disk partials stay resumable).

**NEED computation (receiver), per resource of an incoming asset:**

```
row = resources[(device, id, key)]
if row is done and stat(final).size == row.size:
    if family(type) == original:                     → have
    elif asset.modified_ms == assets[id].modified_ms: → have
    elif type == adjustment_data:                    → want offset 0    (tiny; compared on arrival)
    elif res.size is absent or res.size != row.size:  → want offset 0
    else:                                            → have (provisional; see NEED_MORE)
elif row is partial:                                 → want offset row.durable_offset
elif row is done but final file missing / wrong size: reset row → want offset 0
else (no row):                                       → want offset 0
asset ∈ have  ⇔  no resource of it is wanted, and — in a move job — its XMP sidecar is durable for the
                 current meta (R writes it before sending this NEED if not; WRITER_TESTS X1)
```

Resources the PC holds that are no longer in the manifest (e.g. an edit was reverted) are kept on disk and
marked `orphaned`; the PC never deletes user files.

**NEED_MORE:** when an `adjustment_data` resource arrives (verified) and its sha256 differs from the stored one,
R sends `NEED_MORE` for every edit-family resource of that asset that it had answered as provisional `have`.
R MUST send it before it ACKs that asset. The sender queues those resources and sends another `ASSET_END`
after them. The sender schedules `adjustment_data` first within an asset so NEED_MORE usually arrives early.

### 6.2 Resource transfer

```jsonc
RES_BEGIN { "slot": 0, "id": "…", "key": "photo#0", "offset": 0, "size": 2481234 }
DATA      (binary, §2)
RES_END   { "slot": 0, "size": 2481234, "sha256": "hex64" }
RES_ABORT { "slot": 0, "why": "not_local"|"read_error"|"spool_space"|"asset_gone"|"cancelled" }
ASSET_END { "id": "…", "res_keys": ["photo#0","paired_video#0", …], "complete": true }
          | { "id": "…", "res_keys": [...], "complete": false, "why": "not_local"|"read_error"|
              "spool_space"|"asset_gone"|"retries_exhausted"|"cancelled" }
```

- **Slots**: `0 ≤ slot < WELCOME.max_slots`. A slot is busy from `RES_BEGIN` until the sender sends `RES_END`
  or `RES_ABORT`, and may be reused right after (frames are ordered on one stream).
  `RES_BEGIN` on a busy slot, or `DATA`/`RES_END` on a free slot → protocol error.
- `RES_BEGIN.offset` MUST be either the offset from NEED/NEED_MORE or 0. If 0 and R has a partial, R truncates it.
  If `offset > size` or `offset ≠` R's durable offset (and ≠ 0) → `RES_NACK{why:"bad_offset"}`.
- `DATA.offset` MUST equal the slot's next expected offset; `offset + len(bytes) ≤ size`. Otherwise
  `RES_NACK{bad_offset}` and R discards further DATA for that slot until the next `RES_BEGIN`.
- `RES_END.size` MUST equal `RES_BEGIN.size` and the bytes received; `sha256` covers the **whole file from 0**
  (on resume the sender re-hashes the spool prefix locally).
- `ASSET_END.res_keys` lists **all** current resources of the asset (including ones R already had), so R can
  check completeness against the phone's current truth. It is sent only after every wanted / NEED_MORE resource
  of the asset got `RES_END` (or the asset is `complete:false`).
- Data scheduling (sender): round-robin one DATA frame per busy slot; photo lane 3 slots, video lane 1 slot,
  idle lanes lend slots (ARCHITECTURE §3.6). Chunk = 256 KiB.

### 6.3 ACK / NACK

```jsonc
ACK      { "id":"…", "status":"durable" }
         | { "id":"…", "status":"failed", "failed": [{"key":"photo#0","why":"…"}] }
RES_NACK { "id":"…", "key":"photo#0", "why":"hash_mismatch"|"size_mismatch"|"bad_offset"|"disk_full"|"io",
           "attempt": 1 }
```

- **Invariant [Δ9]:** every asset listed in a `NEED.want` receives exactly one `ACK` in that session
  (unless the session dies first). R sends ACK only after an `ASSET_END` with no outstanding NEED_MORE resources.
- `durable` ⇔ every key in `ASSET_END.res_keys` is in state `done` (file fsynced, renamed, dir fsynced,
  DB committed with `synchronous=FULL`), R has stored the manifest's `modified_ms` (only the NEED trigger in
  §6.1) and **meta** for the asset, and — in a `move` job, or a copy job with `--xmp` — the XMP sidecar
  `<base>.xmp`, generated from the manifest meta alone, is durable (same tmp → fsync → rename → fsync dir path).
  R never parses the received media files to decide this (THREAT_MODEL T3).
- **Meta refresh:** when a NEED computation finds an asset `have` but its manifest meta differs from the stored
  meta, R updates the stored meta and (in a move job, or if a sidecar already exists) rewrites the sidecar
  durably **before** sending that NEED. Meta changes never cause resource re-transfers.
- `failed`: the asset is not durable; nothing is ACKed partially. `complete:false` always yields `failed`.
  A key listed in `ASSET_END.res_keys` that is not `done` is reported as `{key, why:"missing"}`.
- `RES_NACK`: R has deleted its `.part`. The sender retries that resource from offset 0, up to **3 attempts** per
  resource per job; then it sends `ASSET_END{complete:false, why:"retries_exhausted"}`.
  `disk_full` is not retried until R sends `RESUME`. R checks free space **before** creating the `.part`; if
  `free < reserve + size` it answers `RES_NACK{disk_full}` followed by `PAUSE{disk_low}`, re-checks periodically,
  and sends `RESUME` when space returns.
- **Unacked window [Δ11, Δ17]:** with `A = WELCOME.max_unacked_assets` and
  `B = min(WELCOME.max_unacked_bytes, spool_budget)`, where `spool_budget = min(2 GB, 10 % of free space)`
  (recomputed before each export), the sender MUST NOT have more than `A` assets with `ASSET_END` sent and no
  ACK, nor more than `B` bytes spooled-or-sent and not yet ACKed. Exception: a single resource larger than `B` may be
  in flight alone (it still needs the §2.6 free-space guard in ARCHITECTURE). The spool for an asset is deleted on its ACK.

### 6.4 VERIFY / VERIFIED (move only)

```jsonc
VERIFY   { "seq": 0, "assets": [ { "id":"…",
                                   "meta": {"created_ms": …, "fav": false, "loc"?: {"lat":…,"lon":…,"alt"?:…}},
                                   "res": [ {"key":"photo#0","size":2481234,"sha256"?:"hex64"}, … ] } ] }
VERIFIED { "seq": 0, "ok": ["id", …],
           "bad": [ {"id":"…","why":"unknown_asset"|"missing_resource"|"file_missing"|"size_mismatch"|
                     "hash_mismatch", "key"?: "photo#0"} ] }
```

- ≤ 1000 assets per VERIFY frame (and within `MAX_FRAME_LEN`); `seq` increments; one VERIFIED per VERIFY.
- **Fingerprint [Δ10, Δ14]:** an asset's `res` list *is* its content fingerprint: the phone's **current**
  resource keys, each with `size`, and `sha256` **mandatory for every `adjustment_data` key** (tiny export) and
  present for any other resource the phone hashed in this job.
  - `size` comes from the spool file for resources sent in this job, else from the KVC hint. If no size is known
    for a resource, the sender MUST transfer it normally first. No blind deletes.
  - Edits always rewrite `adjustment_data`, so an edit since the PC's copy shows up as a new key, a size change
    or an `adjustment_data` hash change.
- R returns `ok` iff for **every** listed key: row is `done`; final file exists; on-disk size = row size = given
  size; given sha256 (if any) = row sha256; `--paranoid`: file re-hashed = row sha256. Keys R holds that the
  phone no longer lists don't matter. `modified_ms` is **not** a criterion (R9: it may change without edits).
- **Meta in VERIFY [Δ18]:** if `meta` differs from the stored meta (`created_ms` exact; `lat`/`lon` beyond 1e-7°,
  `alt` beyond 0.01 m, presence of `loc`/`alt`, `fav`), R first applies the meta refresh above (stored meta +
  XMP sidecar, durably) and then evaluates the asset normally. VERIFY never returns `ok` for an asset whose
  current meta is not durable on the PC.
- The phone stores the exact fingerprint it sent for each `ok` asset (`job_asset.verified_fp`, canonical form
  below) for the pre-delete guard (§8.4).
- Canonical fingerprint (phone-local only, never on the wire; the Swift implementation is the only producer
  and consumer, but a vector is in `testdata/protocol-vectors.json` so the format is pinned):
  ```
  fp = sha256( meta_line ‖ res_lines )
  meta_line = "meta\t" created_ms "\t" fav "\t" lat "\t" lon "\t" alt "\n"
      created_ms : decimal integer
      fav        : "1" | "0"
      lat, lon   : "%.7f" (C/POSIX locale), or "-" if no location
      alt        : "%.2f", or "-" if no location or no altitude
  res_lines = for each res sorted by key (bytewise): key "\t" size "\t" h "\n"
      size       : decimal integer
      h          : lowercase sha256 hex for adjustment_data keys, else "-"
  ```

### 6.5 Flow control, logs, liveness, close

```jsonc
PAUSE  { "why": "disk_low"|"disk_slow"|"user" }     RESUME { }
LOG    { "lvl": "d"|"i"|"w"|"e", "ts_ms": …, "msg": "≤ 8 KiB UTF-8" }
PING   { "n": 1 }      PONG { "n": 1 }
BYE    { "code": "…", "msg"?: "…", "min"?: 1, "max"?: 1 }
```

- After `PAUSE` the sender MUST stop sending `RES_BEGIN` and `DATA` at the next frame boundary; other frames
  continue. `RESUME` undoes it. PAUSE is not an error and has no timeout.
- `LOG` is lossy: the sender drops LOG frames when its send queue is above 1 MiB.
- Liveness: each side sends `PING` when it has sent nothing for **10 s**; the peer answers `PONG` with the same `n`
  when it reads the PING. **Any** inbound frame resets the peer-dead timer (so DATA keeps the receiver happy while
  R's PINGs flow the other way). A missing PONG is not an error by itself; only inbound silence is.
- **Receiver self-throttle [Δ15]:** when R stops reading the socket on purpose (its writer queue is full, so
  TCP backpressure slows the phone), R MUST suspend its peer-dead timer for that time, and reset it when it
  reads again. R keeps sending PINGs (from a task independent of the reader), so the phone stays satisfied.
  If the writer stays blocked for > **20 s**, R SHOULD send `PAUSE{disk_slow}` so the phone can explain the
  stall, and `RESUME` when it drains.
- While PAUSEd, the sender stops its "ACK after ASSET_END" and "NEED after MANIFEST" timers (§7.3).
- After `BYE` the sender of BYE half-closes and both sides close within 2 s.

---

## 7. Errors, BYE codes, timeouts

### 7.1 BYE codes

| code | sent by | meaning | phone UX / action |
|---|---|---|---|
| `done` | S | job finished | — |
| `user_cancel` | either | user stopped | keep journal, resumable |
| `version_unsupported` | R | no common version | "Update the PC/iPhone app" |
| `auth_failed` | either | bad proof / pair over non-TLS | "Pair again", no auto-retry |
| `unknown_device` | R | device not in DB | "Pair again", no auto-retry |
| `token_invalid` | R | pairing token wrong/expired/used | "Scan a fresh QR code" |
| `protocol_error` | either | §7.2 | auto-retry with backoff, log it |
| `timeout` | either | §7.3 | auto-retry |
| `superseded` | R | same device opened a new session | close quietly |
| `disk_full` | R | cannot continue at all | "PC disk full", no auto-retry |
| `shutting_down` | R | PC app quitting | auto-retry |

### 7.2 Protocol errors (close with `BYE{protocol_error}`)

Frame length 0 or > MAX_FRAME_LEN; unknown type; frame in wrong direction/phase; invalid JSON or missing
required field; DATA payload < 11 bytes; slot out of range or misused; NEED for a page not sent; ACK for an
asset not in want; duplicate asset in a job (except the §6.1 move re-manifest); `RES_BEGIN` for a key not
requested by NEED/NEED_MORE in this session; VERIFY with more than 1,000 assets. (Offset mistakes are recoverable: `RES_NACK{bad_offset}`.)

### 7.3 Timeouts

| What | Limit | On expiry |
|---|---|---|
| TCP connect (phone dialing) | 5 s per address | try next QR/Bonjour address |
| TLS handshake + preface | 10 s | close |
| HELLO → WELCOME (incl. CHALLENGE/AUTH) | 15 s (pairing: 60 s, the PC user confirms) | close |
| Peer silence (no inbound frame) | 30 s | `BYE{timeout}`, close |
| NEED after MANIFEST | 60 s | `BYE{timeout}` |
| ACK after ASSET_END | 300 s | `BYE{timeout}` (R stuck on disk) |
| VERIFIED after VERIFY | 120 s | `BYE{timeout}` |
| Reconnect backoff (dialer) | 1, 2, 4, 8, 16, 30, 30, … s | while a job is active |
| Pairing token TTL | 10 min | `token_invalid` |
| Verify freshness before delete | 10 min | re-VERIFY |

---

## 8. Sender (phone) state machines

### 8.1 Connection

```
IDLE ──job start──► CONNECTING ──tcp+tls ok──► PREFACE ──ok──► HELLO_SENT
HELLO_SENT ──CHALLENGE ok──► AUTH_SENT ──WELCOME──► READY
HELLO_SENT ──WELCOME(paired)──► (store secret) ──PAIRED sent──► READY
READY ──job done & BYE──► IDLE
any ──error/timeout/peer BYE (retryable)──► BACKOFF ──timer──► CONNECTING
any ──BYE auth_failed|unknown_device|token_invalid|version_unsupported|disk_full──► BLOCKED (user action)
```
(USB: CONNECTING is replaced by LISTENING; the PC is the dialer and runs the backoff.)

On entering BACKOFF the sender discards all in-memory per-session state (slots, outstanding pages,
unacked set); the persisted journal (§8.3) is the only thing that survives. On READY it restarts the job
from page 0, omitting journal-`acked` assets when `(pc_id, store_id)` match (§6.1, Δ16); NEED skips the rest
that is already done.

### 8.2 Per asset (one job)

```
queued ─► manifested ─┬─ have ───────────────────────────────────────────► acked*
                      └─ want ─► exporting ─► spooled ─► sending ─► ended ─┬─ ACK durable ─► acked
                                     │            │                         └─ ACK failed ─► failed
                                     └────────────┴── error ─► ASSET_END{complete:false} ─► (ACK failed) ─► failed
move only:  acked ─► verifying ─┬─ ok ─► verified ─► delete_requested ─┬─ deleted
                                └─ bad ─► failed(kept)                ├─ declined (user cancelled prompt)
                                                                      └─ dropped (pre-delete guard failed twice, §8.4)
* "have" assets are acked for the job but still go through VERIFY before deletion.
```

- `exporting`: `writeData(for:toFile:)` into `spool/<job>/<sha256(id) hex>/<res_key>.tmp`, then rename to
  `<res_key>` after the completion handler succeeds (a `.tmp` is never sent). Asset IDs contain `/`, so they are
  hashed for directory names. Spool dir: Application Support, `isExcludedFromBackup`,
  `FileProtectionType.completeUntilFirstUserAuthentication` (readable while locked).
- `sending`: resources in order `adjustment_data` first, then manifest order.
- NEED_MORE in `ended` → back to `exporting` for those keys, then a new ASSET_END.

### 8.3 Persisted journal (phone)

SQLite in Application Support (not a JSON file: at 100k assets an atomic JSON rewrite per ACK is O(n²) total).

```sql
job        (job_id PK, mode, section, label, rules_json, state, created_ms,
            pc_id, store_id)                       -- binding for `acked` omission (Δ16)
job_asset  (job_id, asset_id, state, attempts, last_error,
            verified_fp BLOB, verified_modified_ms, verified_at_ms,   -- Δ14
            reverify_count INTEGER DEFAULT 0,
            dropped_reason TEXT,        -- changed_during_move | not_deletable | not_local | gone | verify_failed
            PRIMARY KEY(job_id, asset_id))
delete_batch(batch_id PK, job_id, state CHECK(state IN ('requested','done','declined')), created_ms)
delete_item (batch_id, asset_id)
```

Persisted states are only `acked`, `failed`, `verified`, `deleted`, `declined`, `dropped`. Everything else is recomputed after
a crash. Writes may be batched (every 1 s); losing the last second only costs a NEED round trip.

### 8.4 Move: delete phase (phone-local, after VERIFIED)

1. For each `verified` asset with `verified_at_ms` < 10 min old by **wall clock** and verified by the **current**
   app process (older, or from before a restart → re-VERIFY first; TRANSFERCORE §7), re-fetch the
   `PHAsset` and check **all** of: it still exists; its **fingerprint** (§6.4) equals `verified_fp`;
   `canPerform(.delete)`; `sourceType == .typeUserLibrary`; not `notLocal`.
   - Fingerprint mismatch with `reverify_count = 0` → set `reverify_count = 1`, put the asset back to `acked`,
     re-manifest it (§6.1 exception; the PC refreshes meta/XMP or requests changed resources), VERIFY again, and
     let it rejoin a later batch. Mismatch again → `dropped` with `dropped_reason = changed_during_move`.
   - Any other failed check → `dropped` with the matching `dropped_reason`.
   - The Done screen lists dropped assets by reason ("3 items kept on iPhone: changed during move").
   Fingerprint shortcut: if `modificationDate` (ms) == `verified_modified_ms`, the fingerprint is taken as
   unchanged (edits always bump modificationDate); otherwise it is recomputed (`assetResources(for:)`, KVC sizes,
   re-export + hash of `adjustment_data`) [Δ14].
   (`deleteAssets` with one undeletable asset fails the whole change block, so filtering is mandatory.)
2. Write `delete_batch(state='requested')` + items, commit.
3. `PHPhotoLibrary.shared().performChanges { PHAssetChangeRequest.deleteAssets(batch) }`.
4. Success → batch `done`, items `deleted`. `PHPhotosError.userCancelled` → batch `declined` (banner offers again).
   Other error → batch `declined`, log, offer retry.

---

## 9. Receiver (PC) state machines

### 9.1 Per resource

```
(none) ──RES_BEGIN──► partial(durable_offset)
partial ──DATA──► partial              (every 64 MiB: fsync .part, commit durable_offset)
partial ──RES_END, size+hash ok──► fsync .part ─► commit verified(sha256) ─► rename ─► fsync dir ─► commit done
partial ──RES_END hash/size bad──► delete .part, row reset ─► RES_NACK
partial ──RES_ABORT not_local|asset_gone──► delete .part, row deleted
partial ──RES_ABORT other | session end──► fsync .part, commit durable_offset = file length
done ──NEED finds file missing/size wrong──► row reset (want offset 0)
done ──re-sent (edit family) ──► new .part → … → rename over existing (atomic replace) → done
```

Rename: Linux `rename(2)` + `fsync(dir)`; Windows `MoveFileExW(MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)`.
SQLite: WAL with `PRAGMA synchronous=FULL` (with `NORMAL`, WAL commits are not durable, so the ACK would lie).

### 9.2 Per asset

```
idle ─(in NEED.want)─► receiving ─ASSET_END(complete) & all keys done & no NEED_MORE outstanding─►
      commit assets.modified_ms ─► ACK durable
receiving ─ASSET_END(complete:false) | any key failed permanently─► ACK failed
```

Final names are allocated once per **asset** (all resources share the base name; collisions get `_2`, `_3`, …),
inside a DB transaction under a per-destination mutex, comparing names **case-insensitively** (NTFS, exFAT
and FAT are case-insensitive, also when mounted on Linux). The chosen `rel_path` is stored at RES_BEGIN.

### 9.3 Session end / supersede

On any session end the receiver: stops reading; for each open slot `fsync .part` and commits
`durable_offset = length`; drops the session's in-memory job state. A superseding session for the same device
waits for this to finish before computing NEED.

---

## 10. Crash matrix

| # | Crash point | State after restart | Recovery | Data lost? |
|---|---|---|---|---|
| P1 | PC: mid DATA | `.part` longer than `durable_offset`, tail maybe garbage | truncate `.part` to `durable_offset`; NEED offers it | ≤ 64 MiB re-sent |
| P2 | PC: after hash ok, before fsync `.part` | row `partial` | as P1 | ≤ 64 MiB |
| P3 | PC: after commit `verified`, before rename | row `verified`, `.part` present | startup: rename + fsync dir → `done` | none |
| P4 | PC: after rename, before commit `done` | row `verified`, `.part` absent, final present | startup: final size == row size → `done` (else reset) | none |
| P5 | PC: after `done` commit, before ACK sent | asset all `done`, phone never got ACK | phone reconnects → NEED says `have` | none |
| P6 | PC: between pairing WELCOME and PAIRED commit | phone has secret, PC doesn't | `unknown_device` → re-pair | — |
| S1 | Phone: during `writeData` | `<key>.tmp` in spool | startup sweep deletes `.tmp` and spool dirs not in an active job | none |
| S2 | Phone: mid send | spool file complete | reconnect → NEED gives PC offset → resume from spool | none |
| S3 | Phone: after ACK, before journal write | asset not `acked` in journal | NEED says `have` → acked again | none |
| S4 | Phone: after VERIFIED, before journal write | not `verified` in journal | re-VERIFY (cheap) | none |
| S5 | Phone: between batch `requested` and result | batch `requested` | fetch item IDs: missing → `deleted`; present → back to `acked`, re-VERIFY | none |
| S6 | Phone killed by iOS in background | as S1–S5 | same | none |
| N1 | Network drop at any point | both sides | §8.1 BACKOFF, §9.3 session end; NEED resumes | ≤ unflushed bytes |

**Safety argument for move:** a PHAsset is deleted only if (a) it is in a VERIFIED `ok` < 10 min old, whose check
covered the phone's full current resource list against `done` rows on the PC whose bytes were hash-verified
at receipt and fsynced before commit, and (b) its content fingerprint (resource keys, sizes, edit-recipe hash)
is unchanged since that check. Any crash before
step 3 of §8.4 leaves the asset on the phone; any crash after it leaves it in Recently Deleted (30 days).

---

## 11. Open items

- O1 (Δ13): USB transport security decision — plain + HMAC auth vs phone-side TLS identity.
- O2: KVC `fileSize` availability on current iOS for all resource types (affects VERIFY of `have` assets
  and the free-space guard). Fallback: export + hash in the VERIFY phase.
- O3: Whether `includeAllBurstAssets` applies to `fetchAssets(in: collection)` or only to library-wide fetches
  (R3 spike); affects the resolver, not the wire format.
- O4: Exact `sourceType`/`canPerform` behaviour for synced-from-computer (iTunes) assets (R4 spike).
- O5: R9 — whether `modificationDate` moves without edits. If it is stable, the exact `modified_ms` check may
  be added back as an extra guard; if edits can ever happen *without* bumping it, the §8.4 shortcut is
  removed and the fingerprint is always recomputed.
- O6: KVC `fileSize` must equal the exported byte count for every resource type (R3/R6 spike); if not, VERIFY
  fails safe (no delete) and `have` assets need a re-export to verify.
