# Build and vet for the Windows target, and produce the Windows test binaries
# that the acceptance jobs upload to a Windows host.
#
# Run by .github/workflows/ci.yml (windows job) and by the self-hosted
# acceptance job.
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

Write-Output '=== gofmt ==='
$unformatted = & gofmt -l internal/ pkg/ tests/ examples/
if ($unformatted) {
    Write-Error ("gofmt needed for:`n" + ($unformatted -join "`n"))
    exit 1
}

Write-Output '=== go build ==='
& go build ./...
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Output '=== go vet ==='
& go vet ./...
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Output '=== cross-compile the Windows test binaries ==='
$out = 'dist/windows'
New-Item -ItemType Directory -Force -Path $out | Out-Null
$env:GOOS = 'windows'
$env:GOARCH = 'amd64'
$env:CGO_ENABLED = '0'

foreach ($pkg in @('internal/agent', 'internal/security', 'internal/packet')) {
    $name = ($pkg -replace '/', '-')
    & go test -c -o "$out/$name.test.exe" "./$pkg/"
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

Write-Output '=== artifacts ==='
Get-ChildItem "$out/*.exe" | ForEach-Object {
    $hash = (Get-FileHash -Algorithm SHA256 $_.FullName).Hash.ToLower()
    Write-Output ("{0}  {1}" -f $hash, $_.Name)
}
