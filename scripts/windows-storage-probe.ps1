#requires -Version 5.1
<#
.SYNOPSIS
Records native Windows filename behavior relevant to rencfs storage portability.
.DESCRIPTION
Uses CreateFileW with CREATE_NEW in isolated temporary directories. Tests both
ordinary and extended paths; does not load Rust, WinFsp, or any encrypted store.
Returns one object per create attempt. Win32Error 0 means a file was created;
other values are observations, not a failed rencfs test. Cleanup errors terminate.
.EXAMPLE
.\scripts\windows-storage-probe.ps1 | Format-Table -AutoSize
.EXAMPLE
.\scripts\windows-storage-probe.ps1 | ConvertTo-Json | Set-Content probe.json
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'This probe requires Windows.'
}

# SafeFileHandle closes every successful CreateFileW handle, including on error.
if (-not ('RencfsStorageProbe.Native' -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace RencfsStorageProbe {
    public static class Native {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
        private static extern SafeFileHandle CreateFileW(string path, uint access,
            uint sharing, IntPtr security, uint disposition, uint attributes, IntPtr template);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DeleteFileW(string path);
        public static int CreateNew(string path) {
            using (SafeFileHandle handle = CreateFileW(path, 0, 7, IntPtr.Zero, 1, 128, IntPtr.Zero)) {
                return handle.IsInvalid ? Marshal.GetLastWin32Error() : 0;
            }
        }
        public static int Delete(string path) {
            return DeleteFileW(path) ? 0 : Marshal.GetLastWin32Error();
        }
    }
}
"@
}

function ConvertTo-ExtendedPath([string] $Path) {
    if ($Path.StartsWith('\\?\')) { return $Path }
    if ($Path.StartsWith('\\')) { return '\\?\UNC\' + $Path.Substring(2) }
    return '\\?\' + $Path
}

$probeRoot = Join-Path ([IO.Path]::GetTempPath()) ('rencfs-storage-probe-' + [guid]::NewGuid().ToString('N'))
$probeRoot = [IO.Path]::GetFullPath($probeRoot)
$directories = New-Object 'System.Collections.Generic.List[string]'
$createdFiles = New-Object 'System.Collections.Generic.List[string]'
$results = New-Object 'System.Collections.Generic.List[object]'
$cases = @(
    @{ Name = 'pipe'; Names = @('encrypted|name') },
    @{ Name = 'dot-entries'; Names = @('$.', '$..') },
    # These distinct unpadded Base64 strings decode to different bytes (00 and 68).
    @{ Name = 'case-distinction'; Names = @('AA', 'aA') },
    @{ Name = 'portable-controls'; Names = @('encrypted_name', 'dot', 'dotdot') }
)

try {
    [IO.Directory]::CreateDirectory($probeRoot) | Out-Null
    foreach ($mode in @('ordinary', 'extended')) {
        foreach ($case in $cases) {
            $directory = Join-Path $probeRoot ($mode + '-' + $case.Name)
            [IO.Directory]::CreateDirectory($directory) | Out-Null
            $directories.Add($directory)
            foreach ($name in $case.Names) {
                $path = Join-Path $directory $name
                if ($mode -eq 'extended') { $path = ConvertTo-ExtendedPath $path }
                $errorCode = [RencfsStorageProbe.Native]::CreateNew($path)
                if ($errorCode -eq 0) {
                    # Ordinary Win32 paths trim terminal dots/spaces. Delete by
                    # the resulting name through an extended path in both modes.
                    $storedName = $name
                    if ($mode -eq 'ordinary') { $storedName = $name.TrimEnd([char[]]'. ') }
                    $createdFiles.Add((ConvertTo-ExtendedPath (Join-Path $directory $storedName)))
                }
                $results.Add([pscustomobject]@{
                    WindowsVersion = [Environment]::OSVersion.Version.ToString()
                    PowerShellVersion = $PSVersionTable.PSVersion.ToString()
                    PathMode = $mode
                    Case = $case.Name
                    Name = $name
                    Created = ($errorCode -eq 0)
                    Win32Error = $errorCode
                })
            }
        }
    }
} finally {
    # Every target is a recorded file inside our GUID directory. No recursive
    # removal, wildcards, user-supplied paths, or traversal of existing stores.
    foreach ($file in $createdFiles) {
        $errorCode = [RencfsStorageProbe.Native]::Delete($file)
        if ($errorCode -ne 0) { throw "Probe cleanup failed (Win32 $errorCode): $file" }
    }
    for ($index = $directories.Count - 1; $index -ge 0; $index--) {
        [IO.Directory]::Delete($directories[$index], $false)
    }
    if ([IO.Directory]::Exists($probeRoot)) { [IO.Directory]::Delete($probeRoot, $false) }
}
$results
