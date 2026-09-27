$ErrorActionPreference = 'Stop'
$taskRecordPath = Join-Path $PSScriptRoot 'teamshelf-runtime\preview-process.json'
if (-not (Test-Path -LiteralPath $taskRecordPath)) { throw 'No preview process record found.' }
$taskRecord = Get-Content -LiteralPath $taskRecordPath -Raw | ConvertFrom-Json
$taskProcess = Get-CimInstance Win32_Process -Filter "ProcessId = $([int]$taskRecord.ProcessId)"
if (-not $taskProcess) { Write-Output 'Preview is already stopped.'; return }
if ($taskProcess.CreationDate.ToUniversalTime().ToString('o') -ne ([datetime]$taskRecord.CreatedUtc).ToUniversalTime().ToString('o') -or
    $taskProcess.CommandLine -ne $taskRecord.CommandLine -or
    $taskProcess.ExecutablePath -ne $taskRecord.ExecutablePath) {
    throw 'Process identity changed. No process was stopped.'
}
Stop-Process -Id $taskProcess.ProcessId
Write-Output 'TeamShelf preview stopped. Data is preserved.'
