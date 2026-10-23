# Run the real-adapter acceptance on a Windows host.
#
# TestWindowsSystemNetworkRealAdapter needs an existing adapter and elevation:
# it sets that adapter's MTU inside a journaled transaction and restores it
# during Rollback.
#
# The adapter is chosen by SIMPLETIER_WINDOWS_ADAPTER. When it is not set, the
# script picks the first non-loopback adapter that is up and has an IPv4
# address, and it records which one it picked.
#
# Elevation: the script re-launches itself elevated through UAC and waits for
# the child to write its result file, because the test needs
# SeNetworkConfigurationPrivilege.
$ErrorActionPreference = 'Continue'

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$outDir = 'dist/windows'
$resultFile = Join-Path $outDir 'real-adapter-result.txt'

function Write-Result([string]$text) {
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    [IO.File]::WriteAllText($resultFile, $text)
}

# Re-launch elevated unless already elevated.
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Output 'not elevated; re-launching through UAC'
    Start-Process powershell -Verb RunAs -Wait -ArgumentList @(
        '-nop', '-ep', 'bypass', '-File', $PSCommandPath
    )
    # The elevated child writes the result file; the parent just relays it.
    if (Test-Path $resultFile) {
        Get-Content $resultFile
        exit 0
    }
    Write-Error 'the elevated run produced no result file'
    exit 1
}

Write-Output ("elevated as " + $id.Name)

# Choose the adapter.
$adapter = $env:SIMPLETIER_WINDOWS_ADAPTER
if (-not $adapter) {
    $candidate = Get-NetAdapter |
        Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -notlike '*Loopback*' } |
        Where-Object { Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue } |
        Select-Object -First 1
    if (-not $candidate) {
        Write-Error 'no up adapter with an IPv4 address was found'
        exit 1
    }
    $adapter = $candidate.Name
    Write-Output ("auto-selected adapter: " + $adapter)
}

$before = Get-NetIPInterface -InterfaceAlias $adapter -AddressFamily IPv4 |
    Select-Object InterfaceAlias, NlMtu
Write-Output '=== MTU before ==='
$before | Format-Table -AutoSize | Out-String -Width 200 | Write-Output

$binary = Join-Path $outDir 'internal-agent.test.exe'
if (-not (Test-Path $binary)) {
    Write-Error "missing $binary; run scripts/test-windows-build.ps1 first"
    exit 1
}

$env:SIMPLETIER_WINDOWS_ADAPTER = $adapter
Write-Output '=== run the real-adapter acceptance ==='
$output = cmd /c "$binary -test.run TestWindowsSystemNetworkRealAdapter -test.v 2>&1"
$exit = $LASTEXITCODE
$output | Write-Output

Write-Output '=== MTU after ==='
Get-NetIPInterface -InterfaceAlias $adapter -AddressFamily IPv4 |
    Select-Object InterfaceAlias, NlMtu | Format-Table -AutoSize | Out-String -Width 200 | Write-Output

Write-Output ("exit=" + $exit)
Write-Result (($output | Out-String) + "`nexit=$exit`nadapter=$adapter`n")
exit $exit
