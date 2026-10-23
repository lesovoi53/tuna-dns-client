# Native core provenance

The Windows core uses MasterDnsVPN (https://github.com/masterking32/MasterDnsVPN), pinned to commit `7de2476f1c33e69eec35360c52810dab43c5c986`.

Input archive: `../../build/public-1.5/upstream/masterdnsvpn-7de2476f1c33e69eec35360c52810dab43c5c986.tar.gz`.
SHA256: `432e2b8b496423da18c80654e3de36fc3646b068d1139b237d6fec540b5162d1`.
If the parent-workspace archive is missing, the build downloads this exact commit from `https://codeload.github.com/masterking32/MasterDnsVPN/tar.gz/7de2476f1c33e69eec35360c52810dab43c5c986` into `.build/downloads`. A different archive hash is fatal. The public download was verified to match the same pinned hash. The build extracts an isolated copy in `.build/core`; Android and external source checkouts are not modified.

Build from the client directory: `powershell -ExecutionPolicy Bypass -File scripts/build-core.ps1`. Optional `-GoExe C:\Go\bin\go.exe` selects a toolchain explicitly; otherwise the script uses `../.tools/go/bin/go.exe` when available, then Go from PATH. Builds use `GOTOOLCHAIN=local`, `GOOS=windows`, `GOARCH=amd64`, `CGO_ENABLED=0`, `-trimpath` and disabled VCS stamping. Validation used Go 1.26.3. Output is `assets/core.exe`. Adapter and upstream configuration tests run by default. Module versions and sums come from the pinned upstream `go.mod` and `go.sum`; Go may require network access to fill an empty module cache. Standalone builds keep Go caches in `.build/go`; the original workspace can reuse its existing `.tools` caches.

The adapter adds private file arguments `-config`, `-resolvers`, and optional `-pairs`. The latter contains a JSON object mapping exact normalized domains to arrays of normalized resolver endpoints (for example `{"a.example":["1.1.1.1:53"]}`). If provided, empty or unknown selections fail closed. The adapter filters the upstream connection map immediately after bootstrap, before MTU scanning and runtime start. Upstream builds that map only during bootstrap. No command-line argument contains an encryption key.

`-validate` checks configuration, codec setup and optional pair selection without networking. `-scan` runs upstream native MTU/tunnel compatibility checks with a three-minute overall deadline. It reports `TUNA_RESOLVER` JSON records containing `domain`, `resolver`, `valid`, `upload` and `download`, followed by `TUNA_SCAN_DONE` or `TUNA_SCAN_FAILED`. A fully completed scan with zero compatible resolvers emits DONE and exits successfully. Cancellation, timeout, empty input and other failures emit FAILED; snapshots accompanying FAILED may contain untested entries. These are actual native compatibility results; there is no latency sorting or synthetic connectivity score.

The isolated upstream overlay adds lifecycle markers from the Android adapter (`TUNA_MASTER_READY`, `TUNA_MASTER_CONNECTING`), connection-stage markers (`TUNA_STAGE_MTU`, `TUNA_STAGE_MTU_FAILED`, `TUNA_STAGE_SESSION`, `TUNA_STAGE_SESSION_RETRY`, `TUNA_STAGE_SESSION_OK`, `TUNA_STAGE_RESET`) and `TUNA_SESSION_RETRY <seconds>` for actual retry backoff. Session success precedes runtime/listener startup; READY is emitted only after listener binding. No marker includes keys or raw errors.

The overlay also emits monotonic `TUNA_SCAN_PROGRESS <completed> <total>` after individual probes complete, using a mutex without reading live connection snapshots. `-scan-workers` selects 1–128 concurrent probes (default 32). A scan-only override prevents upstream adaptive parallelism from raising the selected limit. Connection runtime preserves upstream parallelism. Adapter validation and fatal errors use `TUNA_MASTER_VALID` and `TUNA_MASTER_ERROR`. The pinned upstream supports `RESOLVER_BALANCING_STRATEGY = 5`; the adapter does not remap strategies or change the wire protocol.

Include this directory's license files in distributions. `LICENSE-MasterDnsVPN` is the upstream MIT license. `licenses/` contains the Go runtime license and dependency notices for BurntSushi/toml v1.4.0, klauspost/compress v1.18.5, pierrec/lz4/v4 v4.1.26, golang.org/x/crypto v0.49.0 and golang.org/x/sys v0.42.0.

Local compilation, configuration validation and a negative loopback scan are not proof of connectivity to a deployed DNS tunnel server.

Connection stages emit fixed TUNA_STAGE_MTU, TUNA_STAGE_MTU_FAILED, TUNA_STAGE_SESSION, TUNA_STAGE_SESSION_RETRY, TUNA_STAGE_SESSION_OK and TUNA_STAGE_RESET markers. TUNA_SESSION_RETRY reports the actual backoff in seconds. No raw credential-bearing diagnostics are forwarded to the UI.
