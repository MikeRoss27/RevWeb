<#
.SYNOPSIS
Build and install both webrev binaries, or install a downloaded local bundle.
.EXAMPLE
./scripts/install.ps1
.EXAMPLE
./scripts/install.ps1 -BinaryDir ./target/release -InstallDir ./tools
#>
[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:USERPROFILE '.cargo\bin'),
    [string]$BinaryDir,
    [switch]$AddToPath
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent

if (!$BinaryDir) {
    if (Test-Path -LiteralPath (Join-Path $projectRoot 'bin/webrev.exe')) {
        $BinaryDir = Join-Path $projectRoot 'bin'
    } else {
        foreach ($tool in @('cargo', 'rustc', 'cmake')) {
            if (!(Get-Command $tool -ErrorAction SilentlyContinue)) {
                throw "Missing $tool. See docs/installation.md (Rust 1.89+, Visual Studio C++ build tools, CMake)."
            }
        }
        $rustOutput = & rustc --version
        if ($LASTEXITCODE -ne 0 -or $rustOutput -notmatch 'rustc (\d+\.\d+\.\d+)') {
            throw 'Cannot determine the Rust version.'
        }
        if ([version]$Matches[1] -lt [version]'1.89.0') {
            throw 'Rust 1.89+ is required. Run rustup update stable.'
        }
        Push-Location $projectRoot
        try {
            & cargo build --release --locked --package webrev-cli --package webrev-tui
            if ($LASTEXITCODE -ne 0) {
                throw 'Build failed. Check Visual Studio C++ tools/CMake/NASM; see docs/installation.md.'
            }
        } finally { Pop-Location }
        $BinaryDir = Join-Path $projectRoot 'target/release'
    }
}
$BinaryDir = (Resolve-Path -LiteralPath $BinaryDir).Path
# Verify both files before changing an existing installation.
foreach ($name in @('webrev.exe', 'webrev-tui.exe')) {
    $source = Join-Path $BinaryDir $name
    if (!(Test-Path -LiteralPath $source -PathType Leaf)) { throw "Missing binary: $source" }
    $manifest = Join-Path (Split-Path $BinaryDir -Parent) 'SHA256SUMS'
    if (Test-Path -LiteralPath $manifest) {
        $entry = @(Get-Content -LiteralPath $manifest | Where-Object { $_ -match ('^([0-9a-fA-F]{64})  bin/' + [regex]::Escape($name) + '$') })
        if ($entry.Count -ne 1) { throw "Missing/ambiguous checksum for $name" }
        $expected = $entry[0].Substring(0, 64)
        if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -ne $expected) {
            throw "Checksum mismatch: $source"
        }
    }
}
[void](New-Item -ItemType Directory -Path $InstallDir -Force)
$InstallDir = (Resolve-Path -LiteralPath $InstallDir).Path
foreach ($name in @('webrev.exe', 'webrev-tui.exe')) {
    $source = Join-Path $BinaryDir $name
    $destination = Join-Path $InstallDir $name
    if ($source -ne $destination) { Copy-Item -LiteralPath $source -Destination $destination -Force }
    & $destination --version
    if ($LASTEXITCODE -ne 0) { throw "Installed binary failed: $destination" }
}
if ($AddToPath) {
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ($InstallDir -notin ($userPath -split ';')) {
        [Environment]::SetEnvironmentVariable('Path', "$InstallDir;$userPath", 'User')
    }
    if ($InstallDir -notin ($env:Path -split ';')) { $env:Path = "$InstallDir;$env:Path" }
}
Write-Host "Installed CLI + TUI in $InstallDir"
if ($InstallDir -notin ($env:Path -split ';')) {
    Write-Host 'Add this directory to PATH, or rerun with -AddToPath. Open a new terminal afterwards.'
}
Write-Host 'Static scans are ready. Dynamic scans additionally need Chrome/Chromium (CHROME can point to it).'
