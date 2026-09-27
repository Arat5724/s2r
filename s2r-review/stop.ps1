$ErrorActionPreference = 'Stop'
$taskRecord = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\s2r-review-data\server-process.json'))
if (-not (Test-Path -LiteralPath $taskRecord)) { throw 'No process record exists. No process was stopped.' }
$record = Get-Content -LiteralPath $taskRecord -Raw | ConvertFrom-Json
$server = Get-CimInstance Win32_Process -Filter "ProcessId=$($record.pid)"
if (-not $server) { Write-Output 'S2R Review is already stopped.'; return }
$expectedCreated = ([datetime]$record.created_at).ToUniversalTime()
if ($server.CommandLine -ne $record.command_line -or $server.CreationDate.ToUniversalTime().Ticks -ne $expectedCreated.Ticks -or $server.CommandLine -notlike ('*' + $record.script + '*')) {
    throw 'Process identity does not match the saved record. No process was stopped.'
}
Stop-Process -Id $server.ProcessId
Write-Output 'S2R Review stopped. Saved analyses and the OpenShell worker are preserved.'
