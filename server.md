# Plan: in-process mock Peergos server for tests

## Goal

Run every example / integration test with **no live Java server** by servicing the
client's HTTP contract from in-memory state. Today the examples require a Java
Peergos server on `:7777`; this makes the suite hermetic, fast, and CI-able.

## Key architectural insight

The client funnels *all* server I/O through one trait, `HttpPoster` (`get`,
`post`, `put`). Everything else is built on top of it:

- `HttpStorage(poster)` implements `ContentAddressedStorage` (blocks, champ, links).
- `HttpMutablePointers(poster)` implements `MutablePointers`.
- `signup` / `login` / `social` / space-usage / BATs / MFA call `poster` directly.

So we do **not** implement a socket server or re-implement `ContentAddressedStorage`.
We implement a single **`MockPoster: HttpPoster`** that parses `url` + body and
dispatches to in-memory handlers. Existing `HttpStorage` / `HttpMutablePointers`
wrap it unchanged. Examples swap `ReqwestPoster::new(base)` → `MockPoster::new()`
and keep the rest identical.

Location: new crate `crates/peergos-mock-server` (dev-dependency of `peergos-fs`),
or a `#[cfg(feature = "mock")]` module. Keep it out of the shipping client.

## Shared state model (`Arc<Mutex<MockState>>`)

- `blocks: HashMap<Cid, (Vec<u8> bytes, bool is_raw, PublicKeyHash writer)>` — the
  content-addressed store. Reuse `hash_to_cid` from `peergos-core` so CIDs match.
- `pointers: HashMap<(PublicKeyHash owner, PublicKeyHash writer), (Cid target, u64 seq)>`
  — mutable pointers, with CAS.
- `accounts: HashMap<String username, Account>` where `Account { identity: PublicKeyHash,
  chain: Vec<CborObject> (UserPublicKeyLink), login_data: HashMap<PublicSigningKey, (cbor, auth)>,
  mfa: Vec<MfaMethod> }`.
- `identity_to_username`, and `public_keys: identity → (PublicSigningKey, PublicBoxingKey)`
  recovered from the signup oplog's key blocks.
- `bats: HashMap<PublicKeyHash, Vec<BatWithId>>` (per user; `getUserBats` returns the list).
- `follow_requests: HashMap<PublicKeyHash target, Vec<Vec<u8>>>` — blinded blobs queued
  per recipient (append on `followRequest`, drain on `getFollowRequests`, drop on
  `removeFollowRequest`).
- `secret_links: HashMap<(PublicKeyHash owner, i64 label), CborObject>` — set by the
  login/link write path, read by `link/get`.
- `usage/quota` — derive usage from reachable blocks per owner (see below); fixed quota.
- `server_id: Cid` — a stable fake node id; `link_host: String` (e.g. `"localhost:mock"`).

Reuse: `RamStorage` already models blocks+pointers in memory and enforces CAS +
signature checks — factor its logic into the mock (or delegate block/pointer
handlers to a `RamStorage` instance and add the HTTP-only endpoints around it).

## Endpoint dispatch (URL → handler)

Storage (`api/v0/…`, mostly GET; puts are POST with a cbor body):

| endpoint | does |
|---|---|
| `id` / `ids` | return `server_id` (raw multihash bytes, as the client parses) |
| `transaction/start` / `transaction/close` | return a dummy `TransactionId`; no-op |
| `block/put/bulk?format=…&owner&writer&transaction` | body = `BlockWriteGroup{blocks,signatures}`; **verify each signature** with `writer`'s key over the block hash; store `Cid→bytes`; return the cbor list of CIDs |
| `block/get?arg=<cid>&owner[&bat]` | return raw bytes or 404; optionally check the BAT (see fidelity) |
| `block/stat` | return size |
| `champ/get/bulk?arg=<root>&owner&caps[&committed]` | **reuse `champ_lookup_local`** to walk the champ over stored blocks and return the path+value blocks (this is exactly the server's job) |
| `link/get?label&owner` | return `secret_links[(owner,label)]` |
| `link-host?owner` | return `link_host` string |

Mutable pointers (`peergos/v0/mutable/…`):

| `getPointer?owner&writer` | return the stored signed pointer (or empty) |
| `setPointer` (POST) | body = signed `PointerUpdate`; **verify signature + CAS** (`original` must match current; `sequence` strictly increases); update or reject with the `PointerCasException` the client's merge path expects |
| `setPointers` (POST) | batch of the above, atomic |

Core / PKI (`peergos/v0/core/…`):

| `core/signup` (POST) | body = OpLog (blocks + login data + mirror BAT) + username claim chain + PoW. **Apply**: verify PoW at the required difficulty (else reply `readBoolean(false)+readInt(difficulty)` to trigger the client's retry), verify the claim-chain signature, store all oplog blocks, apply its pointer, register `username→identity`, extract the boxing/signing public keys, store login data + mirror BAT. Return success. |
| `getPublicKey?username` | return the identity `PublicKeyHash` (or the chain) |

Login (`peergos/v0/login/…`, POST):

| `getLogin` | body = signed `{username, author, ...}`; verify the signature by `author`; return the stored `UserStaticData` (entry points) for that login key |
| `setLogin` | store updated login data (verify signature) |
| `listMfa` / `addTotp` / `enableTotp` / `deleteMfa` | manage `Account.mfa`; enough to pass the MFA example (issue a TOTP credential id, verify codes with `mfa::current_totp`) |

Social (`peergos/v0/social/…`, POST):

| `followRequest?target` | append the blob to `follow_requests[target]` |
| `getFollowRequests` | verify the signed request; return the concatenated queued blobs for the caller |
| `removeFollowRequest` | drop a processed blob |

Space usage / BATs:

| `storage/usage?owner&local` / `storage/quota?owner` | verify the time-signed auth; return computed usage / a fixed quota |
| `bats/addBat` (POST) | verify auth; append to `bats[user]` |
| `bats/getUserBats` (POST) | verify auth; return `CborList` of the user's BATs |

## Crypto fidelity — what to actually verify

Verify (cheap, and several tests depend on it):
- **Block-put signatures** and **pointer CAS + signatures** — needed for the
  revocation / concurrent-writer-merge (`buffered` CAS 3-way merge) / owned-writer
  authorization behaviours to be meaningful.
- **Owned-writer authorization on writes** — walk `WriterData.owned` so
  deauthorized/orphaned writers are rejected (needed for `revoke_write`,
  `usage_delete_roundtrip` which assert a writer can no longer write). This is the
  most involved bit; may be phased in after an MVP that trusts the writer.

Verify or stub, with a flag:
- **BAT gating on `block/get`**: initially accept any BAT (return bytes if present).
  Add real BAT auth (`bat.generate_auth` / server-side check) behind a flag to
  exercise the `bat_invariant` gated-read path faithfully.
- **Signup PoW**: implement the difficulty-N check + the reply-with-required-difficulty
  retry, so the client's `signupWithRetry` path is covered; default difficulty low
  (e.g. 8) to keep tests fast, or 0 to skip.

Out of scope: real S3 / DirectS3 presigned URLs (the mock is always
`is_peergos_server = true`, server-side signing), the Java gateway `:9000` website
serving (`public_website_publishing` example — leave on the live server or mock the
gateway separately), post-quantum decapsulation on the server (the server never
needs the ML-KEM secret — it only stores blobs).

## Usage accounting (for `usage_delete_roundtrip`)

Compute `usage(owner)` as the total bytes of blocks reachable from the owner's
pointers (walk each writer's `WriterData → champ tree → nodes → fragments`, sum
unique block sizes). Because the client's delete path nulls unreachable writers and
GCs, this reproduces the "delete returns usage to exactly the prior value" property
without a background GC. Recompute on demand per `storage/usage` call.

## Test-harness integration

- `MockServer::new() -> (Arc<dyn HttpPoster>, Arc<dyn ContentAddressedStorage>, Arc<dyn MutablePointers>)`
  — wires a shared `MockPoster` into `HttpStorage` + `HttpMutablePointers`, mirroring
  how examples build `ReqwestPoster` + `HttpStorage` + `HttpMutablePointers` today.
- Add a `mock_base()` helper the examples accept in place of the `:7777` URL, or
  convert the examples' setup to a shared `fn connect(base: Option<&str>)` that
  returns the mock when no base is given. Examples then run under `cargo test` as
  `#[tokio::test]`s (each gets a fresh `MockServer`, so no cross-run state — this also
  removes the fixed-username hygiene hazard noted for `revoke_write`).
- Keep the ability to point at a real `:7777` (env var) for parity checks.

## Milestones (each unlocks a set of examples)

1. **MVP storage + pointers + signup + login**: block put/get, transaction no-ops,
   champ/get/bulk (reuse local walk), setPointer/getPointer with CAS, signup (PoW +
   oplog apply), getLogin/setLogin. → unlocks `upload`, `mkdir`, `file_section`,
   `multichunk_edit`, `cryptree_cache`, `buffered`, `resume_upload`, `transactions`,
   `upload_subtree`, `hidden_dirs`.
2. **Owned-writer auth + usage**: writer authorization on writes, usage accounting.
   → `move_*`, `delete`, `usage_delete_roundtrip`.
3. **Social + secret links + BATs**: followRequest queue, link/get, getUserBats/addBat,
   link-host. → `share`, `friends`, `incoming*`, `groups`, `social_*`, `create_secret_link`,
   `revoke*`, `dir_sharing_state`, `block_annotate`, `bat_invariant`, `js_methods`.
4. **MFA + account**: listMfa/addTotp/enableTotp/deleteMfa, changePassword, delete_account.
   → `mfa`, `change_password`, `remove_follower`, `delete_account`.

## Status (delivered)

Crate `crates/peergos-mock-server`: `MockServer` + `MockPoster: HttpPoster`,
`MockServer::connect() -> (poster, store, mutable)`. **Zero client changes** — the
existing `HttpStorage`/`HttpMutablePointers`/signup/login/social wrap the mock poster.

Implemented endpoints: storage (`id`, `ids`, `transaction/*`, `block/put/bulk`,
`block/get`, `block/stat`, `champ/get/bulk`, `link/get`, `link-host`), mutable
pointers (`getPointer`/`setPointer`/`setPointers` with CAS), core (`signup` with
OpLog apply + PoW-accept, `getPublicKey`), login (`getLogin`/`setLogin`), space
usage (`usage`/`quota` via block reachability), social (`followRequest`/
`getFollowRequests`/`removeFollowRequest`), BATs (`getUserBats`/`addBat`).

Six end-to-end tests pass in-process (`crates/peergos-fs/tests/mock_e2e.rs`):
signup→upload→sign-in→read, usage delete round-trip, two-user read-share,
secret-link (read-only + password), mutate (rename/move/delete), change-password.
Most other examples use only these endpoints and should run unchanged.

## Known gaps (still need the live server)

- **Owned-writer authorization** — the mock accepts any writer's CAS (it doesn't
  walk the owned-writer champ to reject a *deauthorized* writer). Needed only for
  `revoke_write`/`revoke` to assert bob can no longer write. Blocked on a champ
  key-enumeration helper (`Champ` currently only supports get-by-key). Once that
  exists, walk the owned tree from the owner on each `setPointer` and reject
  unreachable writers.
- **MFA challenge/response** — `listMfa`/`addTotp`/`enableTotp`/`deleteMfa` plus the
  `getLogin` second-factor branch (`a:false` + `MultiFactorAuthRequest`, TOTP
  verification, re-auth). Needed for the `mfa` example only.
- **Website gateway (`:9000`)** — `public_website_publishing` serves a published
  site through the Java gateway; out of scope for a storage/pointer mock.

## Risks / open questions

- **Owned-writer authorization** is the trickiest fidelity point; getting rejection
  semantics exactly right matters for revocation/usage tests. Phase it in and test
  against the live server side-by-side.
- **Signature/CAS wire formats** must match the Java server byte-for-byte
  (`PointerUpdate::serialize`, `SignedPointerUpdate`, the block-put `BlockWriteGroup`)
  — reuse the client's own (de)serializers in the mock, don't re-derive.
- **champ/get/bulk** result ordering/shape must match what `HttpStorage` +
  `RamStorage::load_verified` expect — reuse `champ_lookup_local` verbatim.
- The mock is a **test oracle, not a spec**: keep a subset of examples runnable
  against the real server so the mock can't silently diverge.
