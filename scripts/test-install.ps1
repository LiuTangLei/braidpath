# Pure parsing contracts run anywhere; lifecycle smoke runs on Windows with a real PE fixture.
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$script = Join-Path $root 'install.ps1'
$tokens = $null
$errors = $null
[Management.Automation.Language.Parser]::ParseFile($script, [ref]$tokens, [ref]$errors) | Out-Null
if ($errors.Count) { throw ($errors | Out-String) }
. $script -Architecture arm64
if ((Get-BraidPathArchitecture '386') -ne '386') { throw 'architecture override failed' }
$manifest = ('a' * 64) + '  braidpath-windows-arm64.exe'
if ((Get-BraidPathChecksum $manifest 'braidpath-windows-arm64.exe') -ne ('a' * 64)) { throw 'checksum parse failed' }
$rejected = $false
try { Get-BraidPathChecksum ($manifest + "`n" + $manifest) 'braidpath-windows-arm64.exe' } catch { $rejected = $true }
if (-not $rejected) { throw 'duplicate checksum accepted' }
$rejected = $false
try { Assert-BraidPathVersion 'v1;whoami' } catch { $rejected = $true }
if (-not $rejected) { throw 'invalid version accepted' }
# Exercise the real filesystem replacement on every host, including the .NET
# null-string conversion that otherwise breaks the second Windows installation.
$replaceRoot = Join-Path ([IO.Path]::GetTempPath()) ('braidpath-replace-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($replaceRoot) | Out-Null
try {
    $stage = Join-Path $replaceRoot 'stage'
    $installed = Join-Path $replaceRoot 'installed'
    [IO.File]::WriteAllText($stage, 'first')
    Set-BraidPathBinary $stage $installed
    [IO.File]::WriteAllText($stage, 'second')
    Set-BraidPathBinary $stage $installed
    if ([IO.File]::ReadAllText($installed) -ne 'second' -or (Test-Path $stage)) { throw 'Atomic upgrade failed' }
} finally { Remove-Item -LiteralPath $replaceRoot -Recurse -Force }
$runnerSource = Get-BraidPathRunnerScript
$runnerAst = [Management.Automation.Language.Parser]::ParseInput($runnerSource, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
$quoteFunction = $runnerAst.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'ConvertTo-BraidPathArgument' }, $true)
. ([scriptblock]::Create($quoteFunction.Extent.Text))
$parseFunction = $runnerAst.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'ConvertFrom-BraidPathArguments' }, $true)
. ([scriptblock]::Create($parseFunction.Extent.Text))
$parsingCases = @(
    @{ Json='["one"]'; Values=@('one') },
    @{ Json='["", "two words"]'; Values=@('', 'two words') },
    @{ Json='["2026-10-22T00:00:00Z"]'; Values=@('2026-10-22T00:00:00Z') },
    @{ Json='["2026-10-22T08:00:00+08:00", "literal\nline"]'; Values=@('2026-10-22T08:00:00+08:00', "literal`nline") }
)
foreach ($case in $parsingCases) {
    $parsed = ConvertFrom-BraidPathArguments $case.Json
    if ($parsed -isnot [array] -or ($parsed | Where-Object { $_ -isnot [string] })) { throw 'JSON argument shape lost' }
    if ($parsed.Count -ne $case.Values.Count) { throw 'JSON argument count changed' }
    for ($i = 0; $i -lt $parsed.Count; $i++) {
        if ($parsed[$i] -cne $case.Values[$i]) { throw 'JSON argument text changed' }
    }
}
foreach ($invalidJson in @('[]', '[null]', '[1]', '[["nested"]]', '"scalar"', '{}')) {
    $rejected = $false
    try { ConvertFrom-BraidPathArguments $invalidJson | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw "Invalid argument shape accepted: $invalidJson" }
}
$quotingCases = @(
    @{ Value=''; Encoded='""' },
    @{ Value='one two'; Encoded='"one two"' },
    @{ Value='a"b'; Encoded='"a\"b"' },
    @{ Value='C:\path with spaces\'; Encoded='"C:\path with spaces\\"' },
    @{ Value='slash\"quote'; Encoded='"slash\\\"quote"' }
)
foreach ($case in $quotingCases) {
    if ((ConvertTo-BraidPathArgument $case.Value) -cne $case.Encoded) { throw 'Windows argv escaping failed' }
}
if ([Environment]::OSVersion.Platform -ne 'Win32NT') {
    Write-Output 'PowerShell syntax, atomic replacement and argv contracts passed; Windows lifecycle requires Windows.'
    return
}
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('braidpath-installer-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($testRoot) | Out-Null
try {
    $fixture = Join-Path $testRoot 'fixture.exe'
    Add-Type -TypeDefinition @'
using System;
public class InstallerFixture {
    public static int Main(string[] args) {
        if (args.Length == 1 && args[0] == "--version") Console.WriteLine("braidpath 0.1.0");
        else if (args.Length == 1 && args[0] == "--exit") return 42;
        else foreach (string arg in args) Console.WriteLine(arg);
        return 0;
    }
}
'@ -OutputAssembly $fixture -OutputType ConsoleApplication
    $destination = Join-Path $testRoot "prefix with 'quote"
    function Run-Installer {
        param([string[]]$Options, [bool]$Success = $true)
        $savedPreference = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $script -InstallDir $destination @Options
            $status = $LASTEXITCODE
        } finally { $ErrorActionPreference = $savedPreference }
        if (($status -eq 0) -ne $Success) { throw 'Unexpected installer exit status' }
    }
    Run-Installer @('-Local', $fixture, '-Sha256', (Get-FileHash $fixture).Hash)
    $configPath = Join-Path $destination 'args.json'
    $generated = Get-Content $configPath -Raw | ConvertFrom-Json
    $portIndex = [Array]::IndexOf($generated, '--relay-ports')
    if ($portIndex -lt 0 -or $generated[$portIndex + 1] -ne '44400-44463') { throw 'Missing bounded relay ports' }
    $arguments = @('echo', '', 'with spaces', 'a"b', 'C:\path with spaces\', 'slash\"quote', '$(Write-Error SHOULD_NOT_EVALUATE)')
    $arguments | ConvertTo-Json | Set-Content $configPath -Encoding UTF8
    $actual = @(& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $destination 'run.ps1'))
    if (($actual -join '|') -ne ($arguments -join '|')) { throw 'Arguments were not preserved literally' }
    '["--exit"]' | Set-Content $configPath -Encoding UTF8
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $destination 'run.ps1')
    if ($LASTEXITCODE -ne 42) { throw 'Runner lost native exit status' }
    $arguments | ConvertTo-Json | Set-Content $configPath -Encoding UTF8
    $before = (Get-FileHash (Join-Path $destination 'braidpath.exe')).Hash
    Run-Installer @('-Local', $fixture, '-Sha256', ('0' * 64)) $false
    if ((Get-FileHash (Join-Path $destination 'braidpath.exe')).Hash -ne $before) { throw 'Hash failure replaced binary' }
    $heldLock = [IO.File]::Open((Join-Path $destination 'install.lock'), [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        Run-Installer @('-Local', $fixture) $false
        if ((Get-FileHash (Join-Path $destination 'braidpath.exe')).Hash -ne $before) { throw 'Concurrent installer changed binary' }
    } finally {
        $heldLock.Dispose()
        Remove-Item -LiteralPath (Join-Path $destination 'install.lock')
    }
    Run-Installer @('-Local', $fixture)
    if ((Get-Content $configPath -Raw | ConvertFrom-Json) -join '|' -ne ($arguments -join '|')) { throw 'Upgrade replaced configuration' }
    $state = Join-Path $destination 'state'
    [IO.Directory]::CreateDirectory($state) | Out-Null
    Set-Content (Join-Path $state 'test-key') 'preserve'
    Run-Installer @('-Remove')
    if (-not (Test-Path $configPath) -or -not (Test-Path (Join-Path $state 'test-key'))) { throw 'Uninstall deleted state' }
    if (Test-Path (Join-Path $destination 'braidpath.exe')) { throw 'Uninstall retained executable' }
    Write-Output 'Windows install, upgrade, checksum rejection, literal arguments and preservation passed.'
} finally {
    Remove-Item -LiteralPath $testRoot -Recurse -Force
}
