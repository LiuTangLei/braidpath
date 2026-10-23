# BraidPath installer for Windows PowerShell 5.1 and PowerShell 7.
# SPDX-License-Identifier: Apache-2.0
[CmdletBinding()]
param(
    [string]$Version,
    [string]$Local,
    [string]$Sha256,
    [string]$InstallDir = (Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'BraidPath'),
    [ValidateSet('amd64', 'arm64', '386')][string]$Architecture,
    [switch]$StartupTask,
    [switch]$AddToPath,
    [switch]$Check,
    [switch]$Remove,
    [switch]$DryRun,
    [switch]$PrintTarget
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-BraidPathArchitecture {
    param([string]$Override)
    if ($Override) { return $Override }
    try { $native = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() }
    catch { $native = $env:PROCESSOR_ARCHITEW6432 }
    if (-not $native) { $native = $env:PROCESSOR_ARCHITECTURE }
    switch ($native) {
        'AMD64' { 'amd64' }
        'X64' { 'amd64' }
        'ARM64' { 'arm64' }
        'x86' { '386' }
        default { throw "Unsupported Windows architecture: $native" }
    }
}
function Assert-BraidPathVersion {
    param([string]$Value)
    if ($Value -notmatch '^v[0-9][a-zA-Z0-9._-]*$') { throw "Invalid release version: $Value" }
}
function Get-BraidPathLatest {
    $release = Invoke-RestMethod -Uri 'https://api.github.com/repos/LiuTangLei/braidpath/releases/latest' -Headers @{ 'User-Agent' = 'BraidPath-Installer' }
    Assert-BraidPathVersion $release.tag_name
    return $release.tag_name
}
function Get-BraidPathChecksum {
    param([string]$Manifest, [string]$Asset)
    $entries = @($Manifest -split '\r?\n' | Where-Object { $_ -match ('^[a-fA-F0-9]{64}  ' + [regex]::Escape($Asset) + '$') })
    if ($entries.Count -ne 1) { throw "Missing or duplicate checksum for $Asset" }
    return $entries[0].Substring(0, 64).ToLowerInvariant()
}
function Set-BraidPathBinary {
    param([string]$Stage, [string]$Destination)
    if (Test-Path -LiteralPath $Destination) {
        # PowerShell converts $null to an empty string for .NET string parameters.
        [IO.File]::Replace($Stage, $Destination, [Management.Automation.Language.NullString]::Value)
    } else { [IO.File]::Move($Stage, $Destination) }
}
function Get-BraidPathRunnerScript {
    return @'
# Managed by BraidPath installer
$ErrorActionPreference = 'Stop'
function ConvertTo-BraidPathArgument {
    param([AllowEmptyString()][string]$Value)
    # Quote using Windows argv rules, including empty arguments and trailing slashes.
    '"' + [regex]::Replace([regex]::Replace($Value, '(\\*)"', '$1$1\"'), '(\\+)$', '$1$1') + '"'
}
function ConvertFrom-BraidPathArguments {
    param([string]$Json)
    if ($PSVersionTable.PSEdition -eq 'Core') {
        # ConvertFrom-Json in PowerShell 7.0-7.4 changes date-like strings.
        # Read JSON strings directly; System.Text.Json ships with PowerShell 7.
        $document = [System.Text.Json.JsonDocument]::Parse($Json)
        try {
            if ($document.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Array) { throw 'args.json must contain a JSON array' }
            $values = @(foreach ($item in $document.RootElement.EnumerateArray()) {
                if ($item.ValueKind -ne [System.Text.Json.JsonValueKind]::String) { throw 'args.json must contain only strings' }
                $item.GetString()
            })
        } finally { $document.Dispose() }
    } else {
        # Windows PowerShell 5.1 preserves both array shape and literal strings.
        $values = ConvertFrom-Json -InputObject $Json
    }
    if ($values -isnot [array] -or -not $values.Count) { throw 'args.json must contain a nonempty JSON array of strings' }
    foreach ($value in $values) {
        if ($value -isnot [string]) { throw 'args.json must contain only strings' }
    }
    return ,$values
}
$json = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'args.json') -Raw
$arguments = ConvertFrom-BraidPathArguments $json
$start = New-Object Diagnostics.ProcessStartInfo
$start.FileName = Join-Path $PSScriptRoot 'braidpath.exe'
$start.UseShellExecute = $false
$start.Arguments = (@($arguments | ForEach-Object { ConvertTo-BraidPathArgument $_ }) -join ' ')
$process = [Diagnostics.Process]::Start($start)
try { $process.WaitForExit(); $status = $process.ExitCode }
finally { $process.Dispose() }
exit $status
'@
}
function Invoke-BraidPathInstaller {
    if ($Version -and $Local) { throw '-Version and -Local are mutually exclusive' }
    if ($Sha256 -and (-not $Local -or $Sha256 -notmatch '^[a-fA-F0-9]{64}$')) { throw '-Sha256 requires -Local and 64 hexadecimal characters' }
    if (([int][bool]$Check + [int][bool]$Remove + [int][bool]$PrintTarget) -gt 1) { throw 'Choose only one operation' }
    if (($Check -or $Remove -or $PrintTarget) -and ($Version -or $Local -or $Sha256 -or $StartupTask -or $AddToPath)) { throw 'Install options cannot be used with this operation' }
    if ($Version) { Assert-BraidPathVersion $Version }
    $arch = Get-BraidPathArchitecture $Architecture
    $asset = "braidpath-windows-$arch.exe"
    if ($PrintTarget) { Write-Output $asset; return }
    if ([Environment]::OSVersion.Platform -ne 'Win32NT') { throw 'Use install.sh on Unix systems' }
    if (-not [IO.Path]::IsPathRooted($InstallDir)) { throw '-InstallDir must be absolute' }
    $directory = [IO.Path]::GetFullPath($InstallDir).TrimEnd('\', '/')
    if ($directory -eq [IO.Path]::GetPathRoot($directory).TrimEnd('\', '/')) { throw 'Do not install into a drive root' }
    $binary = Join-Path $directory 'braidpath.exe'
    $runner = Join-Path $directory 'run.ps1'
    $config = Join-Path $directory 'args.json'
    $receipt = Join-Path $directory 'installed.json'
    if ($DryRun) {
        Write-Output "asset=$asset version=$Version install=$directory startupTask=$StartupTask remove=$Remove check=$Check"
        return
    }
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    if ($Check) {
        $latest = Get-BraidPathLatest
        $installed = if (Test-Path -LiteralPath $binary) { & $binary --version } else { 'not-installed' }
        Write-Output "Installed: $installed`nLatest: $latest"
        return
    }
    [IO.Directory]::CreateDirectory($directory) | Out-Null
    $lockPath = Join-Path $directory 'install.lock'
    $lockHandle = [IO.File]::Open($lockPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $stage = Join-Path $directory ('.braidpath-' + [guid]::NewGuid().ToString('N') + '.exe')
    $checksums = Join-Path $directory ('.checksums-' + [guid]::NewGuid().ToString('N'))
    try {
        # Read ownership only while holding the lock; another installer may have
        # completed between entering this function and acquiring it.
        $previous = $null
        if (Test-Path -LiteralPath $receipt) {
            $previous = Get-Content -LiteralPath $receipt -Raw | ConvertFrom-Json
            if ($previous.installer -ne 'BraidPath-v1') { throw 'Unrecognized installation receipt' }
        } elseif (Test-Path -LiteralPath $binary) { throw "Refusing to overwrite unmanaged $binary" }
        if ($Remove -and -not $previous) { throw 'No managed installation here' }
        if ((Test-Path -LiteralPath $runner) -and -not (Select-String -LiteralPath $runner -SimpleMatch 'Managed by BraidPath installer' -Quiet)) { throw 'Refusing to overwrite unmanaged run.ps1' }
        if ($Remove) {
            if ($previous.taskName) {
                $task = Get-ScheduledTask -TaskName $previous.taskName -ErrorAction SilentlyContinue
                if ($task) {
                    if ($task.Description -ne "BraidPath installer: $directory") { throw 'Scheduled task ownership mismatch' }
                    Disable-ScheduledTask -TaskName $previous.taskName | Out-Null
                    Stop-ScheduledTask -TaskName $previous.taskName
                    Unregister-ScheduledTask -TaskName $previous.taskName -Confirm:$false
                }
            }
            foreach ($ownedFile in @($binary, $runner)) {
                if (Test-Path -LiteralPath $ownedFile) { Remove-Item -LiteralPath $ownedFile -Force }
            }
            if ($previous.pathAdded) {
                $parts = @([Environment]::GetEnvironmentVariable('Path', 'User') -split ';' | Where-Object { $_ -and $_.TrimEnd('\') -ine $directory })
                [Environment]::SetEnvironmentVariable('Path', ($parts -join ';'), 'User')
            }
            Remove-Item -LiteralPath $receipt -Force
            Write-Output "Removed BraidPath. Configuration and keys retained in $directory."
            return
        }
        $desired = $Version
        if ($Local) {
            Copy-Item -LiteralPath $Local -Destination $stage
            $expected = $Sha256
        } else {
            if (-not $desired) { $desired = Get-BraidPathLatest }
            $base = "https://github.com/LiuTangLei/braidpath/releases/download/$desired"
            Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS" -OutFile $checksums
            $expected = Get-BraidPathChecksum (Get-Content -LiteralPath $checksums -Raw) $asset
            Invoke-WebRequest -UseBasicParsing -Uri "$base/$asset" -OutFile $stage
        }
        if ($expected -and (Get-FileHash -LiteralPath $stage -Algorithm SHA256).Hash -ine $expected) { throw 'SHA-256 mismatch; installed binary was not changed' }
        $reported = & $stage --version
        if ($LASTEXITCODE -ne 0 -or $reported -notmatch '^braidpath [0-9][a-zA-Z0-9.+-]*$') { throw 'Not a working BraidPath executable' }
        if ($desired -and $reported -ne "braidpath $($desired.Substring(1))") { throw 'Binary version does not match release tag' }
        # Do not silently stop an active user session during an upgrade.
        $running = @(Get-Process -Name braidpath -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $binary })
        if ($running.Count) { throw 'BraidPath is running from this directory. Stop it before upgrading.' }
        if (-not (Test-Path -LiteralPath $config)) {
            $arguments = @('mesh-server', '--dir', (Join-Path $directory 'state\node'), '--id', 'node-1', '--listen', '0.0.0.0:4433', '--advertise', 'CHANGE_ME:4433', '--relay-ports', '44400-44463', '--target', '127.0.0.1:9000')
            $arguments | ConvertTo-Json | Set-Content -LiteralPath $config -Encoding UTF8
        }
        Set-Content -LiteralPath $runner -Value (Get-BraidPathRunnerScript) -Encoding UTF8
        Set-BraidPathBinary $stage $binary
        $taskName = if ($previous) { $previous.taskName } else { '' }
        $pathAdded = if ($previous) { [bool]$previous.pathAdded } else { $false }
        # Save ownership before optional integration so a failed registration can
        # be repaired or uninstalled without adopting an untracked executable.
        function Save-Receipt {
            @{ installer='BraidPath-v1'; version=$reported; taskName=$taskName; pathAdded=$pathAdded } | ConvertTo-Json | Set-Content -LiteralPath $receipt -Encoding UTF8
        }
        Save-Receipt
        if ($StartupTask) {
            $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
            $taskName = 'BraidPath-' + $identity.User.Value
            $existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            if ($existing -and $existing.Description -ne "BraidPath installer: $directory") { throw 'Another install owns this startup task' }
            $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $runner + '"')
            $trigger = New-ScheduledTaskTrigger -AtLogOn -User $identity.Name
            $principal = New-ScheduledTaskPrincipal -UserId $identity.Name -LogonType Interactive -RunLevel Limited
            $settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "BraidPath installer: $directory" -Force | Out-Null
            Save-Receipt
        }
        if ($AddToPath) {
            $userPath = [string][Environment]::GetEnvironmentVariable('Path', 'User')
            if (@($userPath -split ';' | Where-Object { $_.TrimEnd('\') -ieq $directory }).Count -eq 0) {
                [Environment]::SetEnvironmentVariable('Path', (($userPath.TrimEnd(';') + ';' + $directory).TrimStart(';')), 'User')
                $pathAdded = $true
                Save-Receipt
            }
        }
        Write-Output "Installed $reported ($asset) at $binary. Edit $config before starting."
        Write-Output "Run: powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$runner`""
        Write-Output 'No task was started. A registered startup task runs on your next login. Open a new terminal after adding PATH.'
    } finally {
        Remove-Item -LiteralPath $stage, $checksums -Force -ErrorAction SilentlyContinue
        $lockHandle.Dispose()
        Remove-Item -LiteralPath $lockPath -Force
    }
}
if ($MyInvocation.InvocationName -ne '.') { Invoke-BraidPathInstaller }
