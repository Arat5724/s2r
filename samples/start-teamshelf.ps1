param(
    [ValidateSet('baseline', 'hardened')][string]$Profile = 'baseline',
    [int]$Port = 8010,
    [switch]$Reports
)
$ErrorActionPreference = 'Stop'
$taskPython = Join-Path $PSScriptRoot '.venv-teamshelf\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $taskPython)) {
    throw 'Python environment missing. Follow teamshelf/README.md to install dependencies.'
}
$taskArguments = @('-B', 'run.py', '--profile', $Profile, '--port', "$Port")
if ($Reports) { $taskArguments += '--reports' }
Push-Location (Join-Path $PSScriptRoot 'teamshelf')
try { & $taskPython @taskArguments } finally { Pop-Location }
