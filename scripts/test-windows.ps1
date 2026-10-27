# Run from native Windows PowerShell or PowerShell 7, with the MSVC Rust
# toolchain and WinFsp developer/runtime components installed beforehand.
[CmdletBinding()]
param(
    [ValidatePattern('^[D-Zd-z]:$')]
    [string] $Drive = 'R:',
    [string] $TranscriptPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Invoke-Cargo {
    param([string[]] $CargoArgs)
    Write-Host ('cargo ' + ($CargoArgs -join ' '))
    & cargo @CargoArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Cargo command failed with exit code $LASTEXITCODE."
    }
}

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'Run this script on native Windows, not inside WSL.'
}

$Drive = $Drive.ToUpperInvariant()
$driveRoot = $Drive + '\'
if ([Environment]::GetLogicalDrives() -contains $driveRoot) {
    throw "$Drive is already assigned. Choose an unused drive; this script never unmounts an existing drive."
}

$null = Get-Command cargo -ErrorAction Stop
$null = Get-Command rustc -ErrorAction Stop
$rustInfo = & rustc -vV
if ($LASTEXITCODE -ne 0 -or -not ($rustInfo -match '^host: .*-pc-windows-msvc$')) {
    throw 'A native Windows MSVC Rust toolchain is required; use a Visual Studio Developer PowerShell.'
}

$installDirectories = @()
foreach ($key in @('HKLM:\SOFTWARE\WinFsp', 'HKLM:\SOFTWARE\WOW6432Node\WinFsp')) {
    if (Test-Path $key) {
        $installation = Get-ItemProperty -Path $key
        if ($installation.PSObject.Properties.Name -contains 'InstallDir') {
            $installDirectories += [string] $installation.InstallDir
        }
    }
}
foreach ($programDirectory in @(${env:ProgramFiles(x86)}, $env:ProgramFiles)) {
    if ($programDirectory) {
        $installDirectories += Join-Path $programDirectory 'WinFsp'
    }
}
$hasRuntime = $false
foreach ($directory in ($installDirectories | Select-Object -Unique)) {
    foreach ($dll in @('winfsp-x64.dll', 'winfsp-a64.dll', 'winfsp-x86.dll')) {
        if (Test-Path (Join-Path $directory ('bin\' + $dll))) {
            $hasRuntime = $true
        }
    }
}
if (-not $hasRuntime) {
    throw 'WinFsp runtime was not found. Install WinFsp (including Developer files) from https://winfsp.dev/ first. This script does not install drivers.'
}

$previousDrive = [Environment]::GetEnvironmentVariable('RENCFS_TEST_DRIVE', 'Process')
$transcribing = $false
$pushedLocation = $false
try {
    if ($TranscriptPath) {
        $null = Start-Transcript -Path $TranscriptPath -Force
        $transcribing = $true
    }
    Push-Location (Split-Path -Parent $PSScriptRoot)
    $pushedLocation = $true
    $env:RENCFS_TEST_DRIVE = $Drive

    Invoke-Cargo -CargoArgs @('fmt', '--all', '--', '--check')
    Invoke-Cargo -CargoArgs @('build', '--locked', '--release', '--all-targets', '--all-features')
    Invoke-Cargo -CargoArgs @('test', '--locked', '--release', '--lib', 'mount::windows::tests', '--', '--nocapture', '--test-threads=1')
    Invoke-Cargo -CargoArgs @('test', '--locked', '--release', '--test', 'rencfs_windows_itest', '--', '--ignored', '--nocapture', '--test-threads=1')

    if ([Environment]::GetLogicalDrives() -contains $driveRoot) {
        throw "$Drive remains assigned after the test. Investigate the test process; no forced unmount was attempted."
    }
    Write-Host 'Windows callback checks and real mounted-drive roundtrip passed.'
} finally {
    [Environment]::SetEnvironmentVariable('RENCFS_TEST_DRIVE', $previousDrive, 'Process')
    if ($pushedLocation) {
        Pop-Location
    }
    if ($transcribing) {
        $null = Stop-Transcript
    }
}
