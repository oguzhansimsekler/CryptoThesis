# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

A thesis demonstration system for a custom authenticated key-exchange protocol (CTPK / WASM-AKE-V2) running over SignalR between a Blazor WebAssembly client and an ASP.NET Core server. The interactive UI lets a user observe or actively attack the handshake and data phases in real time.

## Solution Structure

The active projects are the **Kripto*** family. The **Crypto*** projects (`CryptoLibrary/`, `CryptoServer/`, `CryptoThesis/`) are older scaffolded placeholders that are no longer the working code.

| Project | Role |
|---|---|
| `KriptoLibrary` | Shared cryptographic library; referenced by all other projects |
| `KriptoServer` | ASP.NET Core SignalR hub server |
| `KriptoClient` | Blazor WebAssembly frontend |
| `KriptoLibrary.Tests` | xUnit unit / security tests |
| `KriptoIntegrationTests` | xUnit integration tests using `WebApplicationFactory` |
| `KriptoMeasurements` | Console micro-benchmark runner |

All projects target **net7.0**. The cryptographic library depends on **BouncyCastle.Cryptography 2.6.2**.

## Commands

Build the entire solution:
```
dotnet build CryptoThesis.sln
```

Run unit + security tests:
```
dotnet test KriptoLibrary.Tests
```

Run integration tests (requires `KriptoServer` to have been built first so its output artefacts exist):
```
dotnet build KriptoServer && dotnet test KriptoIntegrationTests
```

Run a single test by name:
```
dotnet test KriptoLibrary.Tests --filter "FullyQualifiedName~TamperedTag_IsRejectedByServerChannel"
```

Run the performance benchmark:
```
dotnet run --project KriptoMeasurements
```

Run the server (listens on `https://localhost:7214`):
```
dotnet run --project KriptoServer
```

Run the Blazor WebAssembly client (dev server):
```
dotnet run --project KriptoClient
```

## Protocol Architecture

The custom protocol performs a two-message authenticated handshake, then switches to an encrypted data phase:

```
Alice (Client/WASM)          "The Wire" (SignalR)          Bob (Server/.NET)
─────────────────────────────────────────────────────────────────────────────
ClientHello ──────────────────────────────────────────────────────────────►
  SessionId, ClientNonce, ClientEphemeralPublicKey (X25519)

                             ◄──────────────────────────── ServerHello
                               SessionId, ServerNonce, ServerEphemeralPublicKey (X25519),
                               ServerIdentityPublicKey (Ed25519), Signature

Alice: verify pinned key == ServerIdentityPublicKey
Alice: verify Ed25519 signature over WASM-AKE-V2 transcript
Both : ECDH(myEphPriv, peerEphPub) → shared_secret
Both : HKDF-SHA256(ikm=shared_secret, salt=transcriptHash, info="CryptoThesis-Protocol-v1-SessionKeys") → AES-256 key + 12-byte nonce base

Data ─────────────────────────────────────────────────────────────────────►
  SecurePackage { SequenceNumber, Nonce, Ciphertext, Tag }
  Nonce = nonceBase XOR seq (TLS-like construction)
  AAD = big-endian sequence number
  Bob verifies: AES-GCM tag, then sequence number (replay guard)
```

### Key components in `KriptoLibrary`

- **`IdentityService`** — wraps Ed25519 long-term keys; server always has a signing key, client holds only the trusted public key for verification.
- **`HandshakeService`** — generates an ephemeral X25519 key pair and computes the ECDH shared secret.
- **`KeySchedule`** — derives 88 bytes via HKDF-SHA256: first 44 for the Client→Server direction, next 44 for Server→Client. Returns a `SessionKeyMaterial` record.
- **`ProtocolHelpers`** — builds the canonical transcript hash for key schedule binding (`CalculateCanonicalTranscriptHash`) and the byte blob signed by the server (`BuildHandshakeTranscript`).
- **`CryptoProtocolSession`** — top-level session object. After `FinalizeHandshake`, exposes `SendChannel` (outbound) and `ReceiveChannel` (inbound) — each direction uses a different key derived by `KeySchedule`.
- **`SecureChannel`** — stateful AES-256-GCM channel; tracks outbound sequence numbers, enforces strict inbound ordering, and guards against nonce overflow at `ulong.MaxValue`.
- **`SecurePackage`** — wire DTO: `SequenceNumber`, `Nonce`, `Ciphertext`, `Tag`.
- **`ProtocolIdentity`** — exposes `GetPinnedServerPublicKey()` for the client trust anchor. The demo seed is `internal` (`DemoServerSeedHex`); the server reads its private seed from `ServerIdentity:PrivateKeySeed` in `appsettings.json`.

### Server (`KriptoServer`)

`CryptoHub` receives `IdentityService` via constructor injection (registered as singleton in `Program.cs`). Sessions are stored in a static `ConcurrentDictionary<Guid, ServerSessionState>`; a companion `_connectionSessions` dictionary maps `ConnectionId → SessionId` so that `OnDisconnectedAsync` can clean up stale sessions. Hub methods validate message field lengths before processing. The `attackMode` string on each hub method lets the client UI inject attacks server-side (e.g. `TagTamper`, `OutOfOrder`, `SignatureTamper`).

### Client (`KriptoClient`)

`Pages/Home.razor` is the entire UI. It maintains the SignalR connection, drives the protocol state machine, renders "The Wire" (packet log), and implements all attack injection modes client-side as well. Two UI modes exist: **Education** (packets auto-forward) and **Hacker** (user manually forwards or attacks each packet).

The client hardcodes the server hub URL as `https://localhost:7214/cryptohub`.

### Integration tests (`KriptoIntegrationTests`)

Tests use `WebApplicationFactory<Program>` against `KriptoServer` in-process with `HttpTransportType.LongPolling`. The integration test project must copy `KriptoServer` build output artefacts (configured in its `.csproj`) so `WebApplicationFactory` can locate the server's deps/config files.

## Important Design Constraints

- The server's private Ed25519 seed is embedded in `ProtocolIdentity.ServerPrivateSeedHex` for demo purposes. This is intentional for the thesis but must not be treated as production key management.
- Sequence number validation happens **after** AES-GCM authentication to implement fail-closed semantics: a tampered packet is rejected before its sequence number is examined.
- The `CalculateCanonicalTranscriptHash` and `BuildHandshakeTranscript` methods produce **different** byte structures. The former is the HKDF salt; the latter is the data signed by Ed25519. Do not conflate them.
- The `KriptoLibrary` namespace is `CryptoLibrary` (not `KriptoLibrary`) — all types are under `namespace CryptoLibrary`.
