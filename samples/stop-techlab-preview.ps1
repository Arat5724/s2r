$ErrorActionPreference = 'Stop'
$recordPath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'techlab-runtime\server-process.json'))
if (-not (Test-Path -LiteralPath $recordPath)) { throw 'No TechLab process record exists. No process was stopped.' }
$record = Get-Content -LiteralPath $recordPath -Raw | ConvertFrom-Json
$server = Get-CimInstance Win32_Process -Filter "ProcessId=$($record.pid)"
if (-not $server) { Write-Output 'TechLab is already stopped.'; return }
$expectedCreated = ([datetime]$record.created_at).ToUniversalTime()
if ($server.CommandLine -ne $record.command_line -or $server.CreationDate.ToUniversalTime().Ticks -ne $expectedCreated.Ticks -or $server.CommandLine -notlike ('*' + $record.script + '*')) {
    throw 'Process identity does not match the saved record. No process was stopped.'
}
Stop-Process -Id $server.ProcessId
Write-Output 'TechLab preview stopped. Synthetic data is preserved.'
