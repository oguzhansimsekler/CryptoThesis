# ProVerif models

Symbolic models of the handshake (protocol version 3: hybrid X25519 + ML-KEM-768,
Ed25519 signature checked against a pinned key, Finished values in both directions),
the client's first record, and the server's encrypted echo of it. Checked with ProVerif 2.05.

| File | What changes | Expected result |
|---|---|---|
| `handshake.pv` | Main model; the server's signing key is published after the run | Secrecy of the record in both directions, server authentication with key agreement for the client, and key confirmation for the server hold; the honest run is reachable |
| `handshake_nocf.pv` | The server skips the ClientFinished check | Key confirmation for the server fails (shows the query is not vacuous) |
| `handshake_pq.pv` | Every ephemeral X25519 secret is also published after the run | Secrecy still holds (it rests on ML-KEM) |
| `handshake_pq_nokem.pv` | As above, with the ML-KEM secret removed from the key derivation | Secrecy fails (shows the previous result is not vacuous) |
| `handshake_nosig.pv` | The client skips the pinned-key and signature checks | Secrecy and agreement fail: the two-session man-in-the-middle attack |

Run each model with `proverif <file>.pv`. A "RESULT ... is true" line means the property holds;
for the `not event(...)` reachability queries, "is false" means the event can happen.

The models cover one record in each direction. Sequence numbers, ordering, replay of later
records, and truncation are not modelled; the attack tests in `KriptoLibrary.Tests` cover them.
