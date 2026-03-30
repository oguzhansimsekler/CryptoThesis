# Paper Revision Notes

This note aligns the current `CryptoThesis` implementation with the article content extracted from:

- `C:\Users\OguzHan\Desktop\YL_CE_Tez\Makale\Oğuz_Han_Paper.pdf`

## Critical Revisions

### 1. Primitive Names Must Be Updated

The current implementation does **not** use a generic "Curve25519 signature + ECDH" wording.

- Key agreement: `X25519`
- Server authentication: `Ed25519`
- Key schedule: `HKDF-SHA256`
- Data protection: `AES-256-GCM`

Suggested wording:

> The protocol uses X25519 for ephemeral key agreement, Ed25519 for server authentication, HKDF-SHA256 for transcript-bound session key derivation, and AES-256-GCM for authenticated data exchange.

### 2. Authentication Model Must Be Described Correctly

The paper currently contains phrases implying operation "without prior authentication material". That no longer matches the implementation.

Current code behavior:

- the client stores an out-of-band pinned server public key
- the server sends its Ed25519 public key in `ServerHello`
- the client checks both pinned-key equality and the Ed25519 signature

Suggested wording:

> The protocol assumes an out-of-band provisioned trust anchor in the form of a pinned server Ed25519 public key. During the handshake, the client verifies that the received server identity key matches the pinned key and validates the server signature over the handshake transcript before accepting the session.

### 3. Handshake Description Must Be Expanded

The article currently describes a simplified two-message exchange that omits important fields.

Current message structure:

- `ClientHello`: `SessionId`, `ClientNonce`, `ClientEphemeralPublicKey`
- `ServerHello`: `SessionId`, `ServerNonce`, `ServerEphemeralPublicKey`, `ServerIdentityPublicKey`, `Signature`

The signature is computed over:

- client nonce
- server nonce
- client ephemeral public key
- server ephemeral public key
- server identity public key

Suggested wording:

> The client initiates the handshake by transmitting a session identifier, a fresh client nonce, and an ephemeral X25519 public key. The server responds with a fresh server nonce, its ephemeral X25519 public key, its Ed25519 identity public key, and an Ed25519 signature covering the canonical handshake transcript. The client validates the signature and the pinned identity binding before deriving the session key material.

### 4. MITM Discussion Must Credit Authentication, Not Only Transcript Binding

Several passages attribute man-in-the-middle resistance only to transcript-bound HKDF divergence. That is incomplete for the current system.

Current protection comes from two layers:

- pinned server identity validation
- Ed25519 signature verification over the transcript

Transcript binding still matters, but it is not the only reason active interception fails.

Suggested wording:

> Man-in-the-middle resistance is achieved through the combination of transcript binding, explicit server identity binding, and Ed25519 signature verification. Transcript-dependent HKDF prevents context substitution, while pinned-key verification prevents an attacker from introducing an unauthorized server identity.

### 5. WebAssembly Claim Must Be Narrowed

The paper currently suggests that all cryptographic operations are executed inside WebAssembly at both endpoints. That does not match the actual deployment.

Current architecture:

- client-side crypto runs in the Blazor WebAssembly client
- server-side protocol logic runs on ASP.NET Core /.NET
- both sides share the same cryptographic library logic

Suggested wording:

> The client-side cryptographic logic executes in a WebAssembly-based Blazor runtime, while the server-side endpoint executes the corresponding protocol logic in ASP.NET Core on .NET. The same protocol design and cryptographic flow are preserved across both endpoints.

### 6. Performance Section Must Be Rewritten

The current article still includes a `JavaScript` vs `WebAssembly` comparison table and figure. The repository does **not** currently contain a JavaScript benchmark harness implementing the same protocol path.

What the repo currently measures:

- `X25519 Key Generation`
- `HKDF Key Derivation`
- `AES-256-GCM Encryption (1 KB)`
- `AES-256-GCM Decryption (1 KB)`
- `Complete Secure Handshake`

Current measurement source:

- `C:\Users\OguzHan\source\repos\CryptoThesis\KriptoMeasurements\Program.cs`
- `C:\Users\OguzHan\source\repos\CryptoThesis\KriptoClient\Pages\Measurements.razor`

Current average values:

- `X25519 Key Generation`: `0.0963 ms`
- `HKDF Key Derivation`: `0.0103 ms`
- `AES-256-GCM Encryption (1 KB)`: `0.0233 ms`
- `AES-256-GCM Decryption (1 KB)`: `0.0449 ms`
- `Complete Secure Handshake`: `0.3086 ms`

Required article change:

- remove or replace the current `JavaScript` / `WebAssembly` comparison table
- replace `Curve25519 Key Generation` with `X25519 Key Generation`
- describe the results as a `.NET/Blazor-side micro-benchmark set`, unless a real JavaScript comparison harness is later implemented

## Adversary Simulation Status

The article claims runtime adversary testing. The current demo now supports:

- invalid client public key
- server signature tampering
- pinned-key mismatch
- AES-GCM tag tampering
- out-of-order delivery
- replay
- packet drop / suppression
- forged injection with an unknown session identifier

Related code:

- `C:\Users\OguzHan\source\repos\CryptoThesis\KriptoClient\Pages\Home.razor`
- `C:\Users\OguzHan\source\repos\CryptoThesis\KriptoServer\Hubs\CryptoHub.cs`

## Test Evidence

Current automated evidence:

- unit/security tests: `5/5` passing
- integration tests: `3/3` passing

Relevant files:

- `C:\Users\OguzHan\source\repos\CryptoThesis\KriptoLibrary.Tests\ProtocolSecurityTests.cs`
- `C:\Users\OguzHan\source\repos\CryptoThesis\KriptoIntegrationTests\SignalRProtocolFlowTests.cs`

## Candidate Editable Article Sources

The following editable files were found near the PDF:

- `C:\Users\OguzHan\Desktop\YL_CE_Tez\Makale\v4 (1).docx`
- `C:\Users\OguzHan\Desktop\YL_CE_Tez\Makale\v3.docx`
- `C:\Users\OguzHan\Desktop\YL_CE_Tez\Makale\v2.docx`
- `C:\Users\OguzHan\Desktop\YL_CE_Tez\Makale\Modern Web Tarayıcılarında Uçtan Uca Şifreli Haberleşme ve Gerçek Zamanlı ...`

Before editing the article directly, confirm which source file is the latest authoring document.
