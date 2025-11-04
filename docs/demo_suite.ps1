# docs/demo_suite.ps1 — build demo inputs and run showcase commands (robust)
# Requires: PowerShell 7+ (pwsh) recommended

$ErrorActionPreference = "Stop"

function Run-Or-Die {
  param(
    [Parameter(Mandatory=$true)][string]$Cmd,
    [string]$Desc = ""
  )
  Write-Host "`n>>> $Cmd" -ForegroundColor Cyan
  & pwsh -NoLogo -NoProfile -Command $Cmd
  if ($LASTEXITCODE -ne 0) {
    throw "Command failed ($LASTEXITCODE): $Desc`n  $Cmd"
  }
}

# Ensure folders
$root = Get-Location
$docs = Join-Path $root "docs"
$reports = Join-Path $root "surface-scope-reports"
New-Item -ItemType Directory -Force -Path $docs | Out-Null
New-Item -ItemType Directory -Force -Path $reports | Out-Null

# --- Demo input files (idempotent) ---
# targets.json
@'
[
  {"host": "api.example.com"},
  {"host": "staging.example.com"},
  {"host": "rdp.example.com"},
  {"host": "smb.example.com"},
  {"host": "vpn.example.com"},
  {"host": "old-backup.example.com"}
]
'@ | Set-Content -NoNewline -Path (Join-Path $docs "targets.json") -Encoding utf8

# aws_demo.json
@'
{
  "s3": [
    {"name":"example-public-bucket","acl":"public-read","policy_allows_public":true},
    {"name":"legacy-static-site","acl":"public-read","website": true},
    {"name":"private-artifacts","acl":"private"}
  ],
  "ec2": [{"id":"i-01"},{"id":"i-02"},{"id":"i-03"}],
  "iam": [{"role":"PowerUserRole"},{"role":"ReadOnlyRole"}],
  "security_groups": [
    {"id":"sg-02ab...","ingress":[{"cidr":"0.0.0.0/0","port":22}]},
    {"id":"sg-0bad...","ingress":[{"cidr":"0.0.0.0/0","port":3389}]}
  ]
}
'@ | Set-Content -NoNewline -Path (Join-Path $docs "aws_demo.json") -Encoding utf8

# policy.json
@'
{
  "high_any": [22, 3389, 445, 21],
  "med_num_open": 1
}
'@ | Set-Content -NoNewline -Path (Join-Path $docs "policy.json") -Encoding utf8


# --- Showcase commands (each checked for nonzero exit code) ---

# 1) Demo run with paranoid policy + JSON/HTML artifacts
Run-Or-Die -Cmd 'python surface_scope.py run --demo -d acme.corp --policy paranoid --demo-seed 1337 --json-out surface-scope-reports/demo-paranoid.json --html-out surface-scope-reports/demo-paranoid.html' -Desc 'demo-paranoid run'

# 2) scan alias (demo) producing HTML
Run-Or-Die -Cmd 'python surface_scope.py scan --demo --html-out surface-scope-reports/demo-scan.html' -Desc 'scan alias demo'

# 3) Real-mode run from local inputs (no discovery), JSON+HTML
Run-Or-Die -Cmd 'python surface_scope.py run --targets docs\targets.json --cloud-json docs\aws_demo.json --html-out surface-scope-reports/run.html --json-out surface-scope-reports/run.json --timeout 1.5' -Desc 'run with targets+cloud json'

# 4) Quiet mode (should print only short status line)
Run-Or-Die -Cmd 'python surface_scope.py run --demo --html-out surface-scope-reports\quiet.html --quiet' -Desc 'quiet run demo'

# 5) Dry run (no files must be written)
Run-Or-Die -Cmd 'python surface_scope.py run --demo --json-out surface-scope-reports\dry.json --html-out surface-scope-reports\dry.html --no-write' -Desc 'dry-run demo'

Write-Host "`nDemo suite completed successfully." -ForegroundColor Green
