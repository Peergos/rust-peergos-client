# rust-peergos-client

A native Rust implementation of the [Peergos](https://peergos.org) client — a
faithful port of the Java reference client that speaks the same wire protocol and
is validated end-to-end against a live Peergos server and against the Java client for interop.

Peergos is a peer-to-peer, end-to-end encrypted file storage and social platform.
Its security model is a *cryptree*: every file and directory is a tree of
symmetric-key–encrypted nodes, addressed and shared by capability rather than by
ACL, so the server stores only opaque encrypted blocks and never sees plaintext,
filenames, or the directory structure. This crate reimplements that client stack
in Rust with no plaintext or key material ever leaving the process unencrypted.

> Status: functional and exercised against a real server, but pre-1.0. The public
> API is still evolving.

## Architecture

The project is a Cargo workspace of layered crates, each depending only on those
below it:

| Crate | Responsibility |
| --- | --- |
| `peergos-crypto` | Cryptographic primitives: NaCl (Ed25519 signing, box/secretbox) and the hybrid post-quantum key exchange (X25519 + ML-KEM). |
| `peergos-cbor` | A byte-exact CBOR codec whose map ordering and integer encoding match the Java client bit-for-bit (required for content-addressing and signatures). |
| `peergos-multiformats` | CIDv1 / multihash / multibase encoding and the base58/base32 alphabets Peergos uses. |
| `peergos-core` | The network layer: the content-addressed block store client, mutable pointers (signed CAS), the CHAMP hash-array-mapped-trie, the buffered-write network decorator, and direct-to-S3 block access. |
| `peergos-fs` | The cryptree filesystem: files and directories, capabilities, sharing and revocation, social features, publishing, upload transactions, and the ergonomic `FileWrapper` / `UserContext` handles. |

## What it does

- **Accounts** — post-quantum sign-up, sign-in, and MFA/TOTP second factors.
- **Files & directories** — create, read, write, delete, move, rename; multi-chunk
  files streamed with bounded memory; directory listing with chunked children.
- **Capabilities & sharing** — read and write sharing of files and directories with
  other users, capability caches, nested sharing, and access revocation via key
  rotation.
- **Secret links** — create and resolve password-protected shareable links.
- **Social** — follow requests, friends/followers groups, a social feed with posts,
  comments and media, and per-user profiles.
- **Publishing** — make files public and serve a website through the Peergos gateway.
- **Efficient reads** — the server-side `champ/get` lookup returns a whole tree path
  in one round-trip, and every returned block is re-hashed and re-resolved locally so
  a malicious or faulty server cannot forge results.
- **Caching** — a block cache plus a decrypted-cryptree-node cache keyed by the
  content-addressed tree root (so entries can never go stale).
- **Random access** — read or overwrite an arbitrary byte range of a file, touching
  only the chunks that overlap the range rather than the whole file.
- **Crash-safe uploads** — large uploads commit chunk-by-chunk through a transaction
  record, and re-uploading the same content automatically resumes an interrupted
  upload from the first missing chunk.

## Getting started

### Toolchain

A recent stable Rust via [rustup](https://rustup.rs) is required (some dependencies
declare `edition2024`, which older distro rustc cannot parse). Ensure
`~/.cargo/bin` is on your `PATH` so `rust-toolchain.toml` is honoured:

```sh
export PATH="$HOME/.cargo/bin:$PATH"
```

### Build & test

```sh
cargo build --workspace
cargo test  --workspace
```

### Running against a server

The examples talk to a Peergos server (default `http://localhost:7777/`). Point one
up locally, then run any example under `crates/peergos-fs/examples/`:

```sh
# sign in / up, create a home dir, upload and read back a file
cargo run -p peergos-fs --example context -- http://localhost:7777/

# ranged read + in-place ranged overwrite of a multi-chunk file
cargo run -p peergos-fs --example file_section -- http://localhost:7777/

# interrupt a large upload, then auto-resume it by re-uploading the same bytes
cargo run -p peergos-fs --example resume_upload -- http://localhost:7777/
```

There are runnable examples for most features — sharing, revocation, secret links,
social/feed, publishing, the buffered network, upload transactions, and more.

## Using it as a library

`UserContext` is the top-level handle; `FileWrapper` is an ergonomic file/directory
handle in the spirit of the Java client:

```rust
let ctx  = UserContext::sign_in("alice", "password", None, poster, store, mutable).await?;
let home = ctx.get_home().await?;

let dir  = home.mkdir("documents").await?;
let file = dir.upload("notes.txt", b"hello peergos").await?;
assert_eq!(file.read().await?, b"hello peergos");

// read/overwrite a byte range without fetching the whole file
let head = file.read_section(0, 5).await?;
file.overwrite_section(6, b"world").await?;
```

## Design notes

A few places where the port mirrors specific behaviours of the reference client:

- **Verified reads.** Directory and file reads use the server's `champ/get`/`champ/get/bulk`
  API for one-round-trip lookups, but the returned blocks are loaded into a local store
  under their recomputed CIDs and the lookup is re-run locally — so every hash is
  verified client-side and the server is never trusted.
- **Buffered network.** A decorator buffers block writes and pointer updates, flushes
  them in bulk (grouped into cbor / small-raw / large-raw batches with bounded
  concurrency), and resolves concurrent-modification conflicts with a node-level
  three-way CHAMP merge that touches only the changed path.
- **Cryptree cache.** Decrypted nodes are cached by `(tree root, map key)`; because the
  key includes the content-addressed root, a write produces a new root and stale entries
  simply miss. After a write the cache migrates unchanged siblings forward.
- **Content-addressed resume.** Uploads are keyed by their content hash tree, so an
  interrupted upload resumes from the first absent chunk when the same bytes are
  uploaded again.

## Licence

AGPL-3.0-or-later. See `Licence.txt`.
