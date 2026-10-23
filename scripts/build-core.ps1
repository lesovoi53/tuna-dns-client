param([switch]$SkipTests, [string]$GoExe = '')
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$clientRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$repoRoot = Split-Path $clientRoot -Parent
$commit = '7de2476f1c33e69eec35360c52810dab43c5c986'
$archiveSHA = '432e2b8b496423da18c80654e3de36fc3646b068d1139b237d6fec540b5162d1'
$buildRoot = [IO.Path]::GetFullPath((Join-Path $clientRoot '.build'))
$archive = Join-Path $repoRoot "build/public-1.5/upstream/masterdnsvpn-$commit.tar.gz"
$bundledGo = Join-Path $repoRoot '.tools/go/bin/go.exe'
if ($GoExe) {
    $go = (Get-Command $GoExe -CommandType Application -ErrorAction Stop).Source
} elseif (Test-Path -LiteralPath $bundledGo) {
    $go = $bundledGo
} else {
    $go = (Get-Command 'go' -CommandType Application -ErrorAction Stop).Source
}
if (!(Test-Path -LiteralPath $archive)) {
    $downloads = Join-Path $buildRoot 'downloads'
    New-Item -ItemType Directory -Path $downloads -Force | Out-Null
    $archive = Join-Path $downloads "masterdnsvpn-$commit.tar.gz"
    if (!(Test-Path -LiteralPath $archive)) {
        $partial = $archive + '.partial'
        Invoke-WebRequest -UseBasicParsing -Uri "https://codeload.github.com/masterking32/MasterDnsVPN/tar.gz/$commit" -OutFile $partial
        if ((Get-FileHash -LiteralPath $partial -Algorithm SHA256).Hash.ToLowerInvariant() -ne $archiveSHA) { throw 'Downloaded MasterDnsVPN archive hash mismatch' }
        Move-Item -LiteralPath $partial -Destination $archive -Force
    }
}
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $archiveSHA) { throw 'MasterDnsVPN archive hash mismatch' }
$coreRoot = [IO.Path]::GetFullPath((Join-Path $buildRoot 'core'))
# Only replace the reproducible extracted tree, never a checkout or user files.
if ($coreRoot -ne [IO.Path]::GetFullPath((Join-Path $clientRoot '.build/core')) -or !$coreRoot.StartsWith($buildRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe extraction path' }
if (Test-Path -LiteralPath $coreRoot) { Remove-Item -LiteralPath $coreRoot -Recurse -Force }
New-Item -ItemType Directory -Path $coreRoot -Force | Out-Null
& tar -xzf $archive -C $coreRoot --strip-components=1
if ($LASTEXITCODE -ne 0) { throw 'MasterDnsVPN extraction failed' }
$adapterRoot = Join-Path $coreRoot 'cmd/tuna'
New-Item -ItemType Directory -Path $adapterRoot -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $clientRoot 'native/main.go') -Destination $adapterRoot
Copy-Item -LiteralPath (Join-Path $clientRoot 'native/main_test.go') -Destination $adapterRoot

# Apply the Android adapter's log-only lifecycle overlay to our extracted copy.
# Match counts make an unexpected source change fatal.
$utf8 = New-Object System.Text.UTF8Encoding($false)
function Add-Marker([string]$relativePath, [string]$old, [string]$new) {
    $file = Join-Path $coreRoot $relativePath
    $source = [IO.File]::ReadAllText($file).Replace("`r`n", "`n")
    if (($source.Split([string[]]@($old), [StringSplitOptions]::None).Count - 1) -ne 1) { throw "Lifecycle overlay mismatch: $relativePath" }
    [IO.File]::WriteAllText($file, $source.Replace($old, $new), $utf8)
}
Add-Marker 'internal/client/tcp_listener.go' 'l.listeners = listeners' ("l.listeners = listeners`n`t" + 'fmt.Println("TUNA_MASTER_READY")')
Add-Marker 'internal/client/client.go' "c.successMTUChecks = false`n`tc.log.Infof" ("c.successMTUChecks = false`n`t" + 'fmt.Println("TUNA_MASTER_CONNECTING")' + "`n`tc.log.Infof")
Add-Marker 'internal/client/client.go' 'case <-c.sessionResetSignal:' ("case <-c.sessionResetSignal:`n`t`t`t`t" + 'fmt.Println("TUNA_MASTER_CONNECTING")')
Add-Marker 'internal/client/client.go' 'if !c.successMTUChecks {' ('if !c.successMTUChecks {' + "`n`t`t`t`t" + 'fmt.Println("TUNA_STAGE_MTU")')
Add-Marker 'internal/client/client.go' 'if err := c.RunInitialMTUTests(ctx); err != nil {' ('if err := c.RunInitialMTUTests(ctx); err != nil {' + "`n`t`t`t`t`t" + 'fmt.Println("TUNA_STAGE_MTU_FAILED")' + "`n`t`t`t`t`t" + 'fmt.Println("TUNA_SESSION_RETRY 5")')
Add-Marker 'internal/client/client.go' 'if c.syncedUploadMTU <= 0 || c.syncedDownloadMTU <= 0 {' ('if c.syncedUploadMTU <= 0 || c.syncedDownloadMTU <= 0 {' + "`n`t`t`t`t`t" + 'fmt.Println("TUNA_STAGE_MTU_FAILED")' + "`n`t`t`t`t`t" + 'fmt.Println("TUNA_SESSION_RETRY 5")')
Add-Marker 'internal/client/client.go' 'if err := c.InitializeSession(retries); err != nil {' ('fmt.Println("TUNA_STAGE_SESSION")' + "`n`t`t`t`t" + 'if err := c.InitializeSession(retries); err != nil {' + "`n`t`t`t`t`t" + 'fmt.Println("TUNA_STAGE_SESSION_RETRY")')
Add-Marker 'internal/client/client.go' 'c.log.Warnf("<yellow>Session init retry backoff: %s</yellow>", sessionInitRetryDelay)' ('fmt.Printf("TUNA_SESSION_RETRY %d\n", (sessionInitRetryDelay+time.Second-1)/time.Second)' + "`n`t`t`t`t`t" + 'c.log.Warnf("<yellow>Session init retry backoff: %s</yellow>", sessionInitRetryDelay)')
Add-Marker 'internal/client/client.go' 'if err := c.StartAsyncRuntime(ctx); err != nil {' ('fmt.Println("TUNA_STAGE_SESSION_OK")' + "`n`t`t`t`t" + 'if err := c.StartAsyncRuntime(ctx); err != nil {')
Add-Marker 'internal/client/client.go' 'case <-c.sessionResetSignal:' ('case <-c.sessionResetSignal:' + "`n`t`t`t`t" + 'fmt.Println("TUNA_STAGE_RESET")')
Add-Marker 'internal/client/client.go' 'c.log.Warnf("<yellow>Session reset requested, retrying in %s</yellow>", sessionInitRetryDelay)' ('fmt.Printf("TUNA_SESSION_RETRY %d\n", (sessionInitRetryDelay+time.Second-1)/time.Second)' + "`n`t`t`t`t" + 'c.log.Warnf("<yellow>Session reset requested, retrying in %s</yellow>", sessionInitRetryDelay)')
# Scan-only override is set before bootstrap, never changed while workers run.
Add-Marker 'internal/client/mtu.go' 'var ErrNoValidConnections = errors.New("no valid connections after mtu testing")' ('var ErrNoValidConnections = errors.New("no valid connections after mtu testing")' + "`n`n// TUNAScanWorkers is configured once by the standalone scan adapter.`nvar TUNAScanWorkers int")
Add-Marker 'internal/client/mtu.go' 'workerCount := min(max(1, c.cfg.EffectiveMTUTestParallelism()), len(scanConnections))' ('workerCount := min(max(1, c.cfg.EffectiveMTUTestParallelism()), len(scanConnections))' + "`n`tif TUNAScanWorkers > 0 { workerCount = min(TUNAScanWorkers, len(scanConnections)) }")
Add-Marker 'internal/client/mtu.go' 'type mtuScanCounters struct {' ("type mtuScanCounters struct {`n`tprogressMu sync.Mutex`n`tprogressCompleted int")
$probeStart = @'
func (c *Client) runConnectionMTUTest(ctx context.Context, conn Connection, serverID int, total int, maxUploadPayload int, counters *mtuScanCounters) {
	if conn.Key == "" {
		return
	}
'@
$progress = @'
	// Serialize completion and emission, so progress is monotonic even when
	// workers finish concurrently. No connection snapshots are read here.
	defer func() {
		if counters == nil || ctx.Err() != nil { return }
		counters.progressMu.Lock()
		defer counters.progressMu.Unlock()
		counters.progressCompleted++
		fmt.Printf("TUNA_SCAN_PROGRESS %d %d\n", counters.progressCompleted, total)
	}()
'@
Add-Marker 'internal/client/mtu.go' $probeStart.Replace("`r`n", "`n") ($probeStart.Replace("`r`n", "`n") + "`n" + $progress.Replace("`r`n", "`n"))

$savedEnvironment = @{}
foreach ($name in @('GOROOT','GOTOOLCHAIN','GOPATH','GOMODCACHE','GOCACHE','GOOS','GOARCH','CGO_ENABLED')) { $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
try {
    # Discover the chosen executable's own GOROOT, even if the caller used another Go.
    $env:GOROOT = $null
    $env:GOTOOLCHAIN = 'local'
    $goRoot = & $go env GOROOT
    if ($LASTEXITCODE -ne 0) { throw 'Could not determine Go toolchain root' }
    $env:GOROOT = $goRoot
    $cacheRoot = Join-Path $buildRoot 'go'
    if (Test-Path -LiteralPath (Join-Path $repoRoot '.tools/gomodcache')) { $cacheRoot = Join-Path $repoRoot '.tools' }
    $env:GOPATH = $cacheRoot
    $env:GOMODCACHE = Join-Path $cacheRoot 'gomodcache'
    $env:GOCACHE = Join-Path $cacheRoot 'gocache'
    $env:GOOS = 'windows'
    $env:GOARCH = 'amd64'
    $env:CGO_ENABLED = '0'
    Push-Location $coreRoot
    try {
        & $go version
        if ($LASTEXITCODE -ne 0) { throw 'Go toolchain check failed' }
        if (!$SkipTests) {
            & $go test ./cmd/tuna ./internal/config
            if ($LASTEXITCODE -ne 0) { throw 'Native adapter/configuration tests failed' }
        }
        $assets = Join-Path $clientRoot 'assets'
        New-Item -ItemType Directory -Path $assets -Force | Out-Null
        $output = Join-Path $assets 'core.exe'
        & $go build -trimpath -buildvcs=false -ldflags '-s -w' -o $output ./cmd/tuna
        if ($LASTEXITCODE -ne 0) { throw 'Native core build failed' }
        Get-FileHash -LiteralPath $output -Algorithm SHA256
    } finally { Pop-Location }
} finally {
    foreach ($name in $savedEnvironment.Keys) { [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], 'Process') }
}
