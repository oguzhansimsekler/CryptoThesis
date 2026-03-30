# Design, Implementation, and Security Evaluation of a WebAssembly-Assisted Secure Handshake and End-to-End Encryption Protocol

## Abstract

Secure communication over untrusted networks is a fundamental requirement of modern Internet applications, especially in browser-centric systems where application logic, user interaction, and message transport are frequently separated across partially trusted components. This study presents the design, implementation, and security evaluation of an application-layer secure communication protocol built for a browser-assisted client-server environment. The proposed system establishes a secure channel between a Blazor WebAssembly client and an ASP.NET Core server endpoint over a fully untrusted network path. The protocol combines ephemeral X25519 key agreement, Ed25519-based server authentication, transcript-bound HKDF-SHA256 key derivation, and AES-256-GCM authenticated encryption for secure data transmission. Unlike a purely conceptual protocol proposal, the system includes an integrated active adversary simulation layer capable of modifying, replaying, suppressing, reordering, and injecting packets during both the handshake and secure data phases. The study therefore evaluates security not only through design reasoning but also through observable runtime behavior and automated tests. Experimental measurements further show that the introduced cryptographic mechanisms incur low overhead in the current implementation environment. The results demonstrate that strong application-layer confidentiality, integrity, authenticity, replay resistance, and forward secrecy can be achieved in a browser-assisted architecture without depending exclusively on transport-layer protection.

## 1. Introduction

The need for secure communication in distributed applications has increased significantly with the growth of browser-based platforms, real-time collaboration systems, and rich client-side execution models. Although transport-layer protocols such as TLS 1.3 provide strong protection for client-server channels, there are many scenarios in which application developers seek cryptographic guarantees that remain meaningful even when intermediary services, message relays, or surrounding transport infrastructure are not fully trusted. This broader requirement is often discussed under the umbrella of application-layer end-to-end protection.

In browser-based environments, the problem becomes more complex. Client-side code executes within a constrained runtime, often must coordinate with server components over generic web infrastructure, and may need to expose protocol behavior for testing, education, or security validation. At the same time, standard browser cryptographic interfaces tend to prioritize abstraction and usability over low-level protocol experimentation. For a thesis-oriented system that aims not only to protect data but also to explain and validate the security properties of the protection mechanism, explicit control over handshake state, message serialization, attack injection, and verification behavior becomes especially important.

This work focuses on the design and implementation of a secure communication prototype in which a browser-assisted client establishes a cryptographically protected session with a server endpoint over a network path that is treated as adversarial. The system is implemented with a Blazor WebAssembly client, an ASP.NET Core SignalR server, and a shared cryptographic protocol library. The protocol derives its security guarantees from endpoint cryptography rather than from trust in the transport channel. More specifically, the system uses:

- X25519 for ephemeral key agreement,
- Ed25519 for server-side identity authentication,
- HKDF-SHA256 for transcript-bound key derivation,
- AES-256-GCM for authenticated encryption of application data.

In addition to secure session establishment, the prototype includes an active adversary simulation layer integrated into the user interface and message path. This attacker component can manipulate packets during both the handshake and secure data phases, making it possible to observe how the protocol reacts under replay, tampering, out-of-order delivery, suppression, and injection scenarios. This feature is valuable both academically and practically: academically, because it allows concrete discussion of threat models and protocol failures; practically, because it exposes how runtime enforcement behaves under live attack conditions rather than only through abstract argumentation.

The contributions of this study can be summarized as follows:

1. A compact secure handshake and data channel protocol designed for a browser-assisted client-server architecture.
2. An implementation that combines ephemeral key exchange, explicit server authentication, transcript binding, and authenticated encryption.
3. A trust model based on out-of-band server key pinning rather than transport-layer certificates.
4. An integrated attacker simulation environment that supports multiple active adversary behaviors.
5. Unit-level and end-to-end tests that provide executable evidence for key security claims.
6. A performance measurement layer for the protocol's main cryptographic operations.

The remainder of the paper is organized as follows. Section 2 reviews related work. Section 3 defines the threat model and security assumptions. Section 4 presents the system architecture. Section 5 formalizes the mathematical and algorithmic basis of the protocol. Section 6 describes the handshake protocol. Section 7 explains the secure message format. Section 8 discusses the active adversary simulation environment. Section 9 analyzes the security properties of the resulting design. Section 10 presents the performance evaluation. Section 11 concludes the study and discusses future directions.

## 2. Related Work

### 2.1 Secure Communication Protocols

Secure communication over untrusted networks has long been a central topic in applied cryptography. Classical public-key agreement protocols established the foundations for key exchange over insecure channels, and later protocol families transformed these foundations into practical systems for real-world deployment. In the client-server setting, TLS became the dominant standard for protecting transport sessions. TLS 1.3, in particular, strengthened forward secrecy by removing static RSA key transport and standardizing ephemeral Diffie-Hellman-based session establishment. It also incorporates transcript-dependent key derivation and tightly binds handshake context to derived traffic keys.

At the same time, secure messaging systems such as Signal and protocol frameworks such as Noise have shown that strong security properties can be enforced at the application layer rather than being delegated entirely to the transport channel. Signal is especially notable for combining asynchronous key agreement, authenticated identity management, and frequent key evolution. Noise provides reusable handshake patterns based on Diffie-Hellman combinations and transcript hashing. These systems demonstrate that high-assurance communication can be constructed through explicit protocol state and cryptographic context binding.

The current work does not attempt to replace standardized protocols such as TLS 1.3, Signal, or MLS. Rather, it targets a complementary problem: the design of a browser-assisted, application-layer secure channel prototype in which the cryptographic workflow is explicit, inspectable, and suitable for runtime adversary simulation.

### 2.2 Browser-Based Cryptography

Cryptographic support in web applications has traditionally been provided through browser APIs, most prominently the Web Crypto API. These interfaces are standardized and broadly available, but they are typically oriented toward application-level cryptographic use rather than toward detailed experimentation with custom protocol state machines. Developers who wish to expose and inspect transcript construction, packet serialization, failure behavior, or adversarially perturbed message flows often face practical limitations when relying exclusively on higher-level browser-native abstractions.

Modern browser runtimes, however, increasingly support WebAssembly-based execution models that enable portable client-side logic with stronger control over data structures and execution flow. In the .NET ecosystem, Blazor WebAssembly makes it possible to execute managed client logic in a WebAssembly-based runtime. This creates an interesting opportunity for protocol prototyping: the same core cryptographic state machine can be used across client and server components while still allowing the client to execute within a browser-hosted environment.

### 2.3 WebAssembly and Portable Cryptographic Execution

WebAssembly has emerged as a practical medium for deploying logic into browser environments with a higher degree of control than script-only execution models. Research on WebAssembly has highlighted both its performance benefits and its structured, sandboxed execution model. In the context of cryptography, WebAssembly is attractive because it enables consistent client-side implementations that are not tightly bound to the details of specific browser APIs.

For the present prototype, the relevance of WebAssembly lies less in claiming full browser-native parity with handcrafted JavaScript cryptographic implementations and more in enabling a portable client runtime in which protocol logic can be executed, visualized, and attacked in a controlled manner. The client-side component therefore operates in a WebAssembly-assisted environment, while the server executes the corresponding protocol logic on ASP.NET Core.

### 2.4 Security Evaluation with Active Adversaries

Formal protocol analysis remains indispensable, but practical security work frequently benefits from implementation-level validation under live adversarial conditions. Simulation-based testing, attack injection, and protocol fuzzing can reveal how a real implementation behaves when messages are replayed, reordered, altered, or suppressed. In educational and research prototypes, these methods are especially useful because they make security mechanisms observable.

The system presented in this paper incorporates an attacker component directly into the communication flow. This differs from purely offline analysis in that the adversary can operate on actual protocol messages exchanged between endpoints. As a result, the observed acceptance or rejection decisions arise from the implemented cryptographic logic itself rather than from an abstract security claim layered on top of the implementation.

## 3. Threat Model and Assumptions

The security analysis in this work follows a conservative active network adversary model. The communication channel between the client and server is assumed to be fully under attacker control. This model is close in spirit to the classical Dolev-Yao abstraction, with the practical caveat that the adversary is computationally bounded and cannot break standard cryptographic assumptions directly.

### 3.1 Adversary Capabilities

The attacker is assumed to be able to:

- observe all traffic exchanged between the client and server,
- modify handshake messages,
- tamper with ciphertexts and authentication tags,
- replay previously observed packets,
- reorder messages,
- suppress or drop packets,
- inject forged packets,
- attempt session confusion by using mismatched or unknown session identifiers.

These actions may occur during either the handshake phase or the secure data transmission phase. No trust is placed in the network transport itself. The protocol therefore derives its guarantees only from endpoint cryptographic enforcement.

### 3.2 Adversary Limitations

The attacker is not assumed to compromise endpoint private keys or to break the browser or server runtime directly. More concretely:

- the client's ephemeral X25519 private key remains secret,
- the server's Ed25519 private key remains secret,
- the attacker cannot compute valid AES-256-GCM tags without the session key,
- the attacker cannot forge Ed25519 signatures for arbitrary transcripts,
- the attacker cannot solve the underlying key-agreement problem required to derive the shared secret.

Side-channel attacks, memory disclosure attacks, and host compromise are out of scope for the present study.

### 3.3 Endpoint Assumptions

The client and server are assumed to execute the protocol logic correctly. The client is assumed to possess the pinned server Ed25519 public key before the handshake starts. This out-of-band key acts as the protocol's root of trust. Therefore, unlike a fully unauthenticated ephemeral handshake, the present system depends on a minimal authentication bootstrap in the form of pinned key provisioning.

### 3.4 Security Goals

Under the above assumptions, the protocol aims to achieve:

- confidentiality of application data,
- integrity of transported messages,
- authenticity of the server endpoint,
- replay resistance,
- resistance to out-of-order message acceptance,
- forward secrecy through ephemeral key agreement,
- fail-closed rejection of malformed or adversarial packets.

## 4. System Architecture

The system follows a modular browser-assisted client-server architecture. The major components are:

- a Blazor WebAssembly client,
- an ASP.NET Core SignalR server endpoint,
- a shared cryptographic protocol library,
- a visible insecure communication path referred to as "The Wire",
- an interactive attacker control surface integrated into the user interface.

The client is responsible for initiating the handshake, verifying the server identity, deriving session keys, encrypting application data, and processing server responses. The server is responsible for completing the handshake, maintaining session state for active connections, decrypting and validating received secure packets, and reporting success or failure back to the client. The communication path between the two endpoints is intentionally modeled as untrusted and observable.

The architecture supports two complementary modes:

- an educational mode in which packets flow automatically to illustrate normal behavior,
- a hacker mode in which the user can explicitly manipulate packets before forwarding them.

This design serves both the thesis objective and the demonstration objective. From the thesis perspective, it allows experimental validation of security claims. From the educational perspective, it makes cryptographic enforcement visible at the message level.

An important architectural detail is the split execution model:

- client-side protocol logic executes in a WebAssembly-assisted browser runtime,
- server-side protocol logic executes in ASP.NET Core on .NET,
- both sides use the same shared cryptographic flow and message definitions.

Thus, the system is not a pure "all logic in WebAssembly on both endpoints" design. Rather, it is a WebAssembly-assisted secure communication architecture in which the browser endpoint executes the client-side protocol workflow while the server executes the corresponding state machine on .NET.

## 5. Mathematical Model and Algorithmic Flow

### 5.1 X25519-Based Ephemeral Key Agreement

Each session begins with a fresh X25519 ephemeral key pair on the client and a fresh X25519 ephemeral key pair on the server. Let the client choose a private scalar `a` and the server choose a private scalar `b`. The corresponding public keys are computed under the X25519 construction and exchanged during the handshake. Each side then derives the same shared secret:

`K = X25519(a, PubB) = X25519(b, PubA)`

Because the keys are ephemeral and discarded after use, compromise of later application state does not reveal previous session secrets, thereby supporting forward secrecy.

### 5.2 Ed25519-Based Server Authentication

The server owns a long-term Ed25519 identity key pair. The client is provisioned with the server's public key in pinned form before the protocol begins. During the handshake, the server signs the canonical handshake transcript with its Ed25519 private key. The client verifies that:

1. the received server identity public key matches the pinned value, and
2. the Ed25519 signature over the transcript is valid.

Only if both conditions hold does the client accept the server as authentic.

### 5.3 Transcript-Bound HKDF-SHA256

The raw X25519 shared secret is not used directly as an AES key. Instead, the protocol computes a canonical transcript hash that binds:

- client identity context,
- server identity context,
- client ephemeral public key,
- server ephemeral public key,
- client nonce,
- server nonce.

This hash is used as the salt/context input to HKDF-SHA256. The resulting key material is expanded into:

- a 32-byte AES-256 session key,
- a 12-byte nonce base for AES-GCM.

This design provides domain separation and ensures that the session keys are bound to the exact handshake context rather than to the raw shared secret alone.

### 5.4 AES-256-GCM with Sequence-Aware Validation

Application data is protected with AES-256-GCM. For each message:

- a sequence number is incremented,
- a per-message nonce is derived from the session nonce base and the sequence number,
- the sequence number is included as authenticated associated data,
- the plaintext is encrypted and authenticated.

On receipt, the endpoint verifies:

1. structural validity of the packet,
2. the AES-GCM authentication tag,
3. the expected sequence number.

This ordering is important. Ciphertext integrity is checked before plaintext is accepted, and sequence validation ensures that a valid old packet cannot be replayed or accepted out of order.

## 6. Cryptographic Handshake Protocol

### 6.1 Protocol Flow

The handshake uses two protocol messages:

#### ClientHello

The client sends:

- `SessionId`
- `ClientNonce`
- `ClientEphemeralPublicKey`

#### ServerHello

The server responds with:

- `SessionId`
- `ServerNonce`
- `ServerEphemeralPublicKey`
- `ServerIdentityPublicKey`
- `Signature`

The signature authenticates the canonical transcript of the handshake.

### 6.2 Shared Secret and Transcript Binding

After receiving the peer's ephemeral public key, both sides compute the shared X25519 secret. The transcript hash is then computed using the canonical ordering of identities, ephemeral keys, and nonces. This canonical transcript becomes the cryptographic binding context for HKDF-based session key derivation.

### 6.3 Session Key Derivation

The shared secret and transcript hash are passed into HKDF-SHA256. The result is split into:

- an AES-256-GCM encryption key,
- a nonce base.

Both sides derive equivalent values only if they processed the same handshake context.

### 6.4 Explicit Acceptance Conditions

The server may derive tentative session state after receiving `ClientHello`, but the client accepts the secure tunnel only after:

- verifying the pinned server identity key,
- verifying the Ed25519 signature,
- finalizing its own derived session key material.

Therefore, successful key agreement alone is insufficient for acceptance. Server authentication is mandatory in the current implementation.

## 7. Secure Message Format

Once the handshake succeeds, application data is exchanged through secure packets. Each packet contains:

- ciphertext,
- authentication tag,
- nonce,
- sequence number.

The sequence number is incorporated into the authenticated data so that the receiver can distinguish:

- valid new packets,
- replayed packets,
- out-of-order packets,
- structurally malformed packets.

This message format creates a clear separation between:

- cryptographic validity,
- protocol-state validity,
- application-level processing.

If a packet fails at the cryptographic or state-validation stage, it is rejected before any application-visible plaintext is accepted.

## 8. Active Adversary Simulation

The prototype includes an integrated adversary layer that operates directly on visible protocol packets. In hacker mode, the operator can intervene in the message flow and apply attack actions before a packet is forwarded.

The currently supported attack set includes:

- invalid public key substitution in `ClientHello`,
- signature tampering in `ServerHello`,
- pinned-key mismatch in `ServerHello`,
- AES-GCM tag tampering in secure data packets,
- out-of-order delivery,
- replay of previously accepted packets,
- packet suppression or drop,
- forged injection using an unknown session identifier.

This component is central to the contribution of the prototype. It enables runtime observation of how the real implementation reacts when an attacker attempts to violate integrity, ordering, authenticity, or session binding assumptions. In the user interface, the packet flow, security events, and protocol stepper make these decisions visible.

## 9. Security Analysis

### 9.1 Confidentiality

Confidentiality is provided by AES-256-GCM using session keys derived from X25519 and HKDF-SHA256. Because the session keys are not transmitted directly and depend on ephemeral key agreement, an attacker who observes traffic cannot recover plaintext without breaking the underlying cryptographic assumptions.

### 9.2 Integrity and Authenticity

Integrity of application data is enforced by AES-256-GCM authentication tags. Authenticity of the server is enforced by pinned Ed25519 public-key validation and signature verification over the transcript. Therefore, the protocol does not rely on the network channel for either integrity or authenticity.

### 9.3 Replay and Reordering Resistance

Replay and reordering resistance are achieved through authenticated sequence numbers and receiver-side expected-sequence tracking. A duplicated packet may still be structurally well-formed, but it is rejected because its sequence number does not match the receiver's expected inbound state.

### 9.4 Man-in-the-Middle Resistance

It would be incomplete to claim that man-in-the-middle resistance in the present design comes only from transcript-bound HKDF divergence. In fact, the defense is layered:

- transcript binding prevents context substitution,
- pinned-key equality prevents acceptance of an untrusted server identity,
- Ed25519 signature verification prevents tampered server responses from being accepted.

An attacker who modifies handshake material without access to the genuine server signing key and pinned public key cannot complete all checks simultaneously.

### 9.5 Forward Secrecy

Forward secrecy follows from the use of fresh ephemeral X25519 key pairs for each session. Even if long-term application state is later exposed, previously recorded traffic cannot be decrypted retroactively unless the corresponding ephemeral private keys were also compromised.

### 9.6 Fail-Closed Behavior

Malformed, replayed, reordered, or cryptographically invalid packets do not result in partial plaintext exposure. The receiver rejects such messages and reports failure through controlled error handling. This fail-closed behavior is important for both protocol safety and demonstration clarity.

## 10. Performance Evaluation

### 10.1 Experimental Setup

The repository includes a dedicated benchmark harness that measures the latency of the protocol's core cryptographic operations. Measurements were collected with:

- 50 warmup iterations,
- 1000 measurement iterations,
- a 1 KB payload for AES-GCM data operations.

The measured operations are:

- X25519 key generation,
- HKDF key derivation,
- AES-256-GCM encryption for 1 KB payloads,
- AES-256-GCM decryption for 1 KB payloads,
- complete secure handshake.

### 10.2 Important Scope Clarification

The earlier article draft contained a JavaScript versus WebAssembly comparison table. The current repository does not include a parallel JavaScript benchmark harness for the same protocol path. Therefore, the present performance section should not claim a validated JavaScript-versus-WebAssembly micro-benchmark comparison. The valid interpretation of the current data is a measurement of the implemented prototype in the current .NET and Blazor-side environment.

### 10.3 Measured Results

| Operation | Average (ms) | Median (ms) | Min (ms) | Max (ms) | Notes |
|---|---:|---:|---:|---:|---|
| X25519 Key Generation | 0.0963 | 0.0930 | 0.0801 | 0.3521 | Ephemeral key pair generation |
| HKDF Key Derivation | 0.0103 | 0.0089 | 0.0079 | 0.0561 | Transcript-bound derivation |
| AES-256-GCM Encryption (1 KB) | 0.0233 | 0.0221 | 0.0195 | 0.9977 | Authenticated encryption |
| AES-256-GCM Decryption (1 KB) | 0.0449 | 0.0409 | 0.0393 | 2.5099 | Includes tag verification |
| Complete Secure Handshake | 0.3086 | 0.2684 | 0.1899 | 1.4726 | X25519 + Ed25519 + HKDF setup |

### 10.4 Interpretation of Overhead

The complete secure handshake remains low-latency in the current environment. Among the measured primitives, the total handshake cost is naturally larger than isolated key generation or HKDF because it includes:

- ephemeral key agreement,
- transcript construction,
- signature handling,
- key derivation,
- session setup.

AES-256-GCM processing for 1 KB messages remains lightweight, indicating that message-level protection is not the dominant cost in the current prototype.

### 10.5 Summary

The measured values suggest that the current design is suitable for interactive secure communication scenarios. However, any claim about language-level speedup or WebAssembly dominance over JavaScript should be deferred until a genuine JavaScript baseline is implemented and benchmarked under the same workload.

## 11. Conclusion

This paper presented the design and implementation of a WebAssembly-assisted secure communication prototype for browser-centric client-server applications operating over an untrusted network path. The protocol combines X25519 key agreement, Ed25519 server authentication, transcript-bound HKDF-SHA256 key derivation, and AES-256-GCM authenticated encryption to provide confidentiality, integrity, authenticity, replay resistance, and forward secrecy.

Beyond the protocol itself, the work contributes an integrated adversary simulation environment that makes security enforcement observable under realistic active attack scenarios. The implemented system rejects invalid public keys, tampered signatures, pinned-key mismatches, replayed packets, reordered packets, dropped-message disruptions, and forged session injections in accordance with the expected security model. Automated unit and integration tests provide additional executable evidence for these claims.

The current prototype should be viewed as a research and evaluation system rather than as a replacement for standardized secure communication protocols. Its trust model depends on pinned server identity provisioning, and its current performance evaluation is specific to the implemented .NET and Blazor-side benchmark environment. Nevertheless, the prototype demonstrates that strong application-layer protection and meaningful runtime security validation can be achieved in a browser-assisted architecture without placing trust in the network channel itself.

Future work may extend the system in several directions:

- migration to a supported modern .NET target framework,
- richer trust-establishment mechanisms such as certificate-based provisioning,
- side-channel-aware implementation analysis,
- formal protocol modeling,
- genuine JavaScript baseline benchmarking,
- possible experimentation with post-quantum key-establishment alternatives.

## References

[1] W. Diffie and M. Hellman, "New Directions in Cryptography," IEEE Transactions on Information Theory, vol. 22, no. 6, pp. 644-654, 1976.

[2] D. J. Bernstein, "Curve25519: New Diffie-Hellman Speed Records," PKC 2006, Springer, pp. 207-228, 2006.

[3] S. Josefsson and I. Liusvaara, "Edwards-Curve Digital Signature Algorithm (EdDSA)," RFC 8032, IETF, 2017.

[4] H. Krawczyk and P. Eronen, "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)," RFC 5869, IETF, 2010.

[5] M. Dworkin, "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM)," NIST SP 800-38D, 2007.

[6] E. Rescorla, "The Transport Layer Security (TLS) Protocol Version 1.3," RFC 8446, IETF, 2018.

[7] D. Dolev and A. Yao, "On the Security of Public Key Protocols," IEEE Transactions on Information Theory, vol. 29, no. 2, pp. 198-208, 1983.

[8] World Wide Web Consortium, "WebAssembly Core Specification," W3C Recommendation, 2019.

[9] J. Katz and Y. Lindell, Introduction to Modern Cryptography, 2nd ed., Chapman and Hall/CRC, 2014.

[10] T. Perrin, "The Noise Protocol Framework," 2018.

[11] M. Marlinspike and T. Perrin, "The Signal Protocol," 2016.
