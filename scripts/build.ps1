param([string]$Version='0.1.2',[string]$GoExe='')
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$go = Join-Path (Split-Path $root -Parent) '.tools/go/bin/go.exe'
if ($GoExe) { $go=$GoExe } elseif (!(Test-Path -LiteralPath $go)) { $go=(Get-Command go -ErrorAction Stop).Source }
if (!(Test-Path -LiteralPath (Join-Path $root 'assets/core.exe'))) { throw 'Run build-core.ps1 first' }
if (Test-Path (Join-Path (Split-Path $root -Parent) '.tools/gocache')) { $env:GOCACHE = Join-Path (Split-Path $root -Parent) '.tools/gocache' }
if (Test-Path (Join-Path (Split-Path $root -Parent) '.tools/gomodcache')) { $env:GOMODCACHE = Join-Path (Split-Path $root -Parent) '.tools/gomodcache' }
$env:CGO_ENABLED = '0'
$env:GOOS = 'windows'
$env:GOARCH = 'amd64'
Push-Location $root
try {
 & $go test ./...
 if ($LASTEXITCODE -ne 0) { throw 'Tests failed' }
 & $go vet ./...
 if ($LASTEXITCODE -ne 0) { throw 'Vet failed' }
 New-Item -ItemType Directory -Path dist -Force | Out-Null
 $exe="TUNA-DNS-Client-$Version.exe"
 & $go build -buildvcs=false -trimpath -ldflags '-s -w -H=windowsgui' -o "dist/$exe" .
 if ($LASTEXITCODE -ne 0) { throw 'Build failed' }
 $stage = Join-Path $root "dist/package-$Version"
 New-Item -ItemType Directory -Path $stage -Force | Out-Null
 Copy-Item "dist/$exe",README.md,VALIDATION.md,LICENSE -Destination $stage
 Copy-Item -LiteralPath native -Destination $stage -Recurse -Force
 Compress-Archive -Path "$stage/*" -DestinationPath "dist/TUNA-DNS-Client-$Version-Windows-x64.zip" -Force
 Get-FileHash "dist/$exe","dist/TUNA-DNS-Client-$Version-Windows-x64.zip" -Algorithm SHA256 | Format-Table -AutoSize
} finally { Pop-Location }
