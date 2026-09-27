param([string]$PythonPath = '')
$ErrorActionPreference = 'Stop'
$runtime = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'techlab-runtime'))
if (-not (Test-Path -LiteralPath $runtime)) { New-Item -ItemType Directory -Path $runtime | Out-Null }
if (-not $PythonPath) { $PythonPath = Join-Path $PSScriptRoot '.venv-teamshelf\Scripts\python.exe' }
$PythonPath = (Resolve-Path -LiteralPath $PythonPath).Path
$existing = Get-NetTCPConnection -LocalAddress '127.0.0.1' -LocalPort 8010 -State Listen -ErrorAction SilentlyContinue
if ($existing) { throw 'Port 8010 is already in use. Inspect the existing process before starting TechLab.' }
$scriptFile = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot 'techlab\run.py')).Path
$launcher = Start-Process -FilePath $PythonPath -ArgumentList '-B', ('"' + $scriptFile + '"'), '--port', '8010' -WorkingDirectory (Join-Path $PSScriptRoot 'techlab') -WindowStyle Hidden -RedirectStandardOutput (Join-Path $runtime 'server.out.log') -RedirectStandardError (Join-Path $runtime 'server.err.log') -PassThru
$listener = $null
for ($i = 0; $i -lt 40; $i++) {
    Start-Sleep -Milliseconds 250
    $listener = Get-NetTCPConnection -LocalAddress '127.0.0.1' -LocalPort 8010 -State Listen -ErrorAction SilentlyContinue
    if ($listener) { break }
}
if (-not $listener) { throw 'TechLab startup failed. Inspect samples/techlab-runtime/server.err.log.' }
$server = Get-CimInstance Win32_Process -Filter "ProcessId=$($listener.OwningProcess)"
if (-not $server -or $server.CommandLine -notlike ('*' + $scriptFile + '*')) {
    throw 'Unexpected process on port 8010; no process was stopped.'
}
$record = @{ pid = $server.ProcessId; created_at = $server.CreationDate.ToUniversalTime().ToString('o'); command_line = $server.CommandLine; script = $scriptFile }
$record | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $runtime 'server-process.json') -Encoding utf8
Write-Output 'TechLab is ready: http://127.0.0.1:8010'
