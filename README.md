# CryptoThesis

A browser-hosted secure channel and a testbed for attacking it. The client runs in
Blazor WebAssembly, the server on ASP.NET Core, and the two talk over SignalR. An
attacker on the message path can change, replay, reorder, drop, and inject messages
while the protocol runs, and every attack has an automated test that asserts which
check rejects it.

The protocol: a hybrid X25519 + ML-KEM-768 key exchange, an Ed25519 signature over the
transcript checked against a pinned server key, HKDF-SHA256 salted with a transcript
hash, Finished MACs in both directions, and AES-256-GCM records with authenticated
sequence numbers.

## Projects

| Folder | Contents |
|---|---|
| `KriptoLibrary` | Protocol code shared by client and server (namespace `CryptoLibrary`) |
| `KriptoServer` | ASP.NET Core server with the SignalR hub |
| `KriptoClient` | Blazor WebAssembly client: the interactive testbed and the in-browser benchmark |
| `KriptoLibrary.Tests` | Attack tests A2-A33 that run on the library, plus protocol tests |
| `KriptoIntegrationTests` | Attack tests that need the hub (A1, A7, A18-A22, A25, A26, A34, A35) |
| `KriptoBenchmarks` | Benchmark and dudect routines shared by the native runner and the browser page |
| `KriptoMeasurements` | Native benchmark runner |
| `proverif` | ProVerif models; see `proverif/README.md` |
| `benchmarks` | Raw measurement data and the scripts that turn it into tables |

The `Crypto*` folders are an earlier scaffold and are not used.

## Requirements

- .NET 10 SDK
- For the AOT build of the client: the `wasm-tools` workload (`dotnet workload install wasm-tools`, as administrator on Windows)
- For the tables: Node.js
- For the models: ProVerif 2.05

## Running the testbed

```
dotnet run --project KriptoServer --launch-profile https   # https://localhost:7214
dotnet run --project KriptoClient --launch-profile http    # http://localhost:5283
```

Open the client, choose education mode (messages are forwarded automatically) or hacker
mode (each message waits on the Wire panel to be forwarded or attacked).

## Reproducing the results

Attack and protocol tests:

```
dotnet test KriptoLibrary.Tests
dotnet build KriptoServer
dotnet test KriptoIntegrationTests
```

Test names start with the attack number used in the paper, for example
`A25_RejectingCheck_DependsOnTheOrderOfChecks`.

ProVerif models:

```
cd proverif
proverif handshake.pv
```

and likewise for the other four files; `proverif/README.md` lists the expected results.

Native benchmark and timing test, pinned to one core:

```
dotnet build -c Release KriptoMeasurements
dotnet run -c Release --project KriptoMeasurements --no-build -- --batched --core 2
dotnet run -c Release --project KriptoMeasurements --no-build -- --dudect 1000000 --core 2
dotnet run -c Release --project KriptoMeasurements --no-build -- --dudect 10000000 --only Ed25519 --core 2
```

Each run writes a JSON file to `benchmarks/`.

Browser benchmark: start the client in Release mode for the interpreter build,

```
dotnet run -c Release --project KriptoClient --launch-profile http
```

or publish it with AOT compilation and serve the `wwwroot` folder of the output:

```
dotnet publish KriptoClient -c Release -p:RunAOTCompilation=true -o <folder>
```

Then open `/wasm-benchmark`, keep the tab in the foreground, and press *Run benchmark*,
*Run WebCrypto*, or *Run noble*. Each button downloads a JSON file; copy it to `benchmarks/`.

Tables: `node benchmarks/make_tables.js` prints the table rows from the newest file of each
kind, and `node benchmarks/fill_paper_tables.js <main.tex>` writes them between the
`% BEGIN rows:` and `% END rows:` markers of the paper.

## Data

`benchmarks/` holds the measurements of the current version (.NET 10, BouncyCastle 2.7.0),
`benchmarks/net7/` those of the same protocol on .NET 7 and BouncyCastle 2.6.2, and
`benchmarks/v2/` those of the earlier protocol version without ML-KEM and Finished messages.

## Note on keys

The server's Ed25519 seed in `appsettings.json` and the matching pinned key in the client
are demonstration values. They are public and must not be used to protect anything.
