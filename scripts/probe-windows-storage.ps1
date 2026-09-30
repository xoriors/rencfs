#Requires -Version 5.1
<#
.SYNOPSIS Observe Win32 backing-store assumptions without mounting rencfs.
.DESCRIPTION Creates empty files in a unique temporary directory and removes it.
No Rust, WinFsp, elevation, or existing vault is required.
#>
[CmdletBinding()]
param([string] $ParentDirectory = [IO.Path]::GetTempPath())
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'This probe requires Windows.' }
if (-not ('RencfsStorageProbe.Native' -as [type])) {
    $native = @(
'using System;'
'using System.Runtime.InteropServices;'
'using Microsoft.Win32.SafeHandles;'
'namespace RencfsStorageProbe {'
' public static class Native {'
'  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]'
'  private static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);'
'  public static int Open(string path, bool create, bool directory) {'
'   using (SafeFileHandle h = CreateFileW(path, 0x80000000, 7, IntPtr.Zero, create ? 1u : 3u, directory ? 0x02000000u : 0u, IntPtr.Zero))'
'    return h.IsInvalid ? Marshal.GetLastWin32Error() : 0;'
'  }'
' }'
'}'
    ) -join [Environment]::NewLine
    Add-Type -TypeDefinition $native
}
$parent = (Resolve-Path -LiteralPath $ParentDirectory).ProviderPath
if (-not [IO.Directory]::Exists($parent)) { throw 'ParentDirectory must be an existing directory.' }
$probePath = Join-Path $parent ('rencfs-storage-probe-' + [Guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($probePath)
function Invoke-FileProbe([string] $Name, [string] $Purpose) {
    $code = [RencfsStorageProbe.Native]::Open((Join-Path $probePath $Name), $true, $false)
    [pscustomobject]@{ Probe=$Purpose; RequestedName=$Name; Win32Error=$code
        Result=if ($code -eq 0) {'Created'} else {[ComponentModel.Win32Exception]::new($code).Message} }
}
try {
    Invoke-FileProbe 'ab|cd' 'Encrypted-name alphabet contains pipe'
    Invoke-FileProbe '$.' 'Dot entry storage marker'
    Invoke-FileProbe '$..' 'Parent entry storage marker'
    Invoke-FileProbe 'QUJD' 'Mixed-case storage name, first spelling'
    Invoke-FileProbe 'qujd' 'Mixed-case storage name, second spelling'
    foreach ($directoryFlag in @($false,$true)) {
        $code=[RencfsStorageProbe.Native]::Open($probePath,$false,$directoryFlag)
        [pscustomobject]@{ Probe='Open directory; FILE_FLAG_BACKUP_SEMANTICS='+$directoryFlag
            RequestedName='(probe directory)'; Win32Error=$code
            Result=if ($code -eq 0) {'Opened (durability not tested)'} else {[ComponentModel.Win32Exception]::new($code).Message} }
    }
    [pscustomobject]@{ Probe='Actual directory entries'; RequestedName='(enumeration)'; Win32Error=0
        Result=(([IO.Directory]::GetFiles($probePath) | ForEach-Object {[IO.Path]::GetFileName($_)} | Sort-Object) -join ', ') }
} finally {
    foreach ($file in [IO.Directory]::GetFiles($probePath)) {[IO.File]::Delete($file)}
    [IO.Directory]::Delete($probePath,$false)
}
