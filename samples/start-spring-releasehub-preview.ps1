param([string]$JavaPath = '')
$ErrorActionPreference = 'Stop'

$project = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'spring-releasehub'))
$runtime = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'spring-releasehub-runtime'))
if (-not (Test-Path -LiteralPath $runtime)) { New-Item -ItemType Directory -Path $runtime | Out-Null }
$existing = Get-NetTCPConnection -LocalAddress '127.0.0.1' -LocalPort 8030 -State Listen -ErrorAction SilentlyContinue
if ($existing) { throw 'Port 8030 is already in use. Inspect the existing process before starting ReleaseHub.' }

if (-not $JavaPath) { $JavaPath = (Get-Command java -ErrorAction Stop).Source }
$JavaPath = (Resolve-Path -LiteralPath $JavaPath).Path
$wrapper = Join-Path $project 'mvnw.cmd'
if (-not (Test-Path -LiteralPath $wrapper)) { throw 'Maven Wrapper is missing from the Spring sample.' }
Push-Location $project
try {
    & $wrapper -B -q -DskipTests package
    if ($LASTEXITCODE -ne 0) { throw 'ReleaseHub build failed.' }
} finally { Pop-Location }

$jar = (Resolve-Path -LiteralPath (Join-Path $project 'target\spring-releasehub-0.1.0.jar')).Path
Start-Process -FilePath $JavaPath -ArgumentList '-jar', ('"' + $jar + '"') -WorkingDirectory $project -WindowStyle Hidden `
    -RedirectStandardOutput (Join-Path $runtime 'server.out.log') `
    -RedirectStandardError (Join-Path $runtime 'server.err.log') | Out-Null
$listener = $null
for ($i = 0; $i -lt 100; $i++) {
    Start-Sleep -Milliseconds 300
    $listener = Get-NetTCPConnection -LocalAddress '127.0.0.1' -LocalPort 8030 -State Listen -ErrorAction SilentlyContinue
    if ($listener) { break }
}
if (-not $listener) { throw 'ReleaseHub startup failed. Inspect samples/spring-releasehub-runtime/server.err.log.' }
$server = $null
for ($i = 0; $i -lt 20; $i++) {
    $server = Get-CimInstance Win32_Process -Filter "ProcessId=$($listener.OwningProcess)"
    if ($server -and $server.CommandLine.Replace('\\', '\') -like ('*' + $jar + '*')) { break }
    Start-Sleep -Milliseconds 100
}
if (-not $server -or $server.CommandLine.Replace('\\', '\') -notlike ('*' + $jar + '*')) {
    throw 'Unexpected process on port 8030; no process was stopped.'
}
$record = @{ pid = $server.ProcessId; created_at = $server.CreationDate.ToUniversalTime().ToString('o');
             command_line = $server.CommandLine; jar = $jar }
$record | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $runtime 'server-process.json') -Encoding utf8
Write-Output 'ReleaseHub is ready: http://127.0.0.1:8030'
