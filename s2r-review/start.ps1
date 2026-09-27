param([string]$PythonPath = '')
$ErrorActionPreference = 'Stop'
$taskData = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\s2r-review-data'))
if (-not (Test-Path -LiteralPath $taskData)) { New-Item -ItemType Directory -Path $taskData | Out-Null }
if (-not $PythonPath) {
    $PythonPath = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
    if (-not (Test-Path -LiteralPath $PythonPath)) {
        $PythonPath = Join-Path $PSScriptRoot '..\samples\.venv-teamshelf\Scripts\python.exe'
    }
}
$PythonPath = (Resolve-Path -LiteralPath $PythonPath).Path
$existing = Get-NetTCPConnection -LocalAddress '127.0.0.1' -LocalPort 8020 -State Listen -ErrorAction SilentlyContinue
if ($existing) { throw 'Port 8020 is already in use. Open http://127.0.0.1:8020 or inspect the existing process.' }
$scriptFile = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot 'run.py')).Path
$launcher = Start-Process -FilePath $PythonPath -ArgumentList '-B', ('"' + $scriptFile + '"') -WorkingDirectory $PSScriptRoot -WindowStyle Hidden -RedirectStandardOutput (Join-Path $taskData 'server.out.log') -RedirectStandardError (Join-Path $taskData 'server.err.log') -PassThru
$listener = $null
for ($i = 0; $i -lt 40; $i++) {
    Start-Sleep -Milliseconds 250
    $listener = Get-NetTCPConnection -LocalAddress '127.0.0.1' -LocalPort 8020 -State Listen -ErrorAction SilentlyContinue
    if ($listener) { break }
}
if (-not $listener) { throw 'Startup failed. Inspect s2r-review-data/server.err.log.' }
$server = Get-CimInstance Win32_Process -Filter "ProcessId=$($listener.OwningProcess)"
if (-not $server -or $server.CommandLine -notlike ('*' + $scriptFile + '*')) { throw 'Unexpected process on port 8020; no process was stopped.' }
$record = @{ pid = $server.ProcessId; created_at = $server.CreationDate.ToUniversalTime().ToString('o'); command_line = $server.CommandLine; script = $scriptFile }
$record | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $taskData 'server-process.json') -Encoding utf8
Write-Output 'S2R Review is ready: http://127.0.0.1:8020'
