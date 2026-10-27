# Run in a fresh native 64-bit PowerShell after building java_bridge.dll.
# This checks DLL loading before WinFsp initialization, not JNI mount behavior.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $DllPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or [IntPtr]::Size -ne 8) {
    throw 'Run this check in a fresh native 64-bit Windows PowerShell process.'
}
$dll = (Resolve-Path -LiteralPath $DllPath -ErrorAction Stop).ProviderPath

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class RencfsJavaBridgeLoader
{
    [DllImport("kernel32.dll", EntryPoint = "LoadLibraryExW", CharSet = CharSet.Unicode,
        ExactSpelling = true, SetLastError = true)]
    public static extern IntPtr LoadLibraryEx(string path, IntPtr file, uint flags);

    [DllImport("kernel32.dll", EntryPoint = "GetModuleHandleW", CharSet = CharSet.Unicode,
        ExactSpelling = true, SetLastError = true)]
    public static extern IntPtr GetModuleHandle(string name);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr module, string name);

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool FreeLibrary(IntPtr module);
}
'@

$winfspDlls = @('winfsp-x64.dll', 'winfsp-x86.dll', 'winfsp-a64.dll')
foreach ($name in $winfspDlls) {
    if ([RencfsJavaBridgeLoader]::GetModuleHandle($name) -ne [IntPtr]::Zero) {
        throw "$name is already loaded. Repeat the check in a fresh PowerShell process."
    }
}

# LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32.
# PATH, the current directory and user-added DLL directories are excluded.
$module = [RencfsJavaBridgeLoader]::LoadLibraryEx($dll, [IntPtr]::Zero, 0x00000900)
if ($module -eq [IntPtr]::Zero) {
    $code = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    $detail = New-Object ComponentModel.Win32Exception -ArgumentList $code
    throw "Cannot load java_bridge.dll (Win32 error ${code}): $($detail.Message)"
}

try {
    if ([RencfsJavaBridgeLoader]::GetProcAddress($module, 'Java_RustLibrary_mount') -eq [IntPtr]::Zero) {
        throw 'The loaded DLL does not export Java_RustLibrary_mount.'
    }
    foreach ($name in $winfspDlls) {
        if ([RencfsJavaBridgeLoader]::GetModuleHandle($name) -ne [IntPtr]::Zero) {
            throw "$name loaded eagerly before mount initialization."
        }
    }
} finally {
    if (-not [RencfsJavaBridgeLoader]::FreeLibrary($module)) {
        throw 'FreeLibrary failed for java_bridge.dll.'
    }
}

Write-Host 'Java bridge DLL load check passed; WinFsp stayed unloaded before mount initialization.'
