# docs/demo_suite.ps1 — build demo inputs and run showcase commands
$ErrorActionPreference = "Stop"

$root = Get-Location
$docs = Join-Path -Path $root -ChildPath "docs"
$reports = Join-Path -Path $root -ChildPath "surface-scope-reports"

New-Item -ItemType Directory -Force -Path $docs | Out-Null
New-Item -ItemType Directory -Force -Path $reports | Out-Null

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

# 1) Demo with custom policy JSON (label becomes custom(policy.json))
$demoJson = Join-Path $reports "demo-paranoid.json"
$demoHtml = Join-Path $reports "demo-paranoid.html"
python surface_scope.py run --demo -d acme.corp --policy balanced --policy-json (Join-Path $docs "policy.json") --demo-seed 1337 --json-out $demoJson --html-out $demoHtml
if (!(Test-Path $demoJson)) { throw "Missing $demoJson" }
if (!(Test-Path $demoHtml)) { throw "Missing $demoHtml" }

# 2) Quiet demo (HTML only, suppressed body but prints confirmation)
$scanHtml = Join-Path $reports "demo-scan.html"
python surface_scope.py scan --demo --html-out $scanHtml --quiet
if (!(Test-Path $scanHtml)) { throw "Missing $scanHtml" }

# 3) Real-ish run with offline inputs
$runHtml = Join-Path $reports "run.html"
$runJson = Join-Path $reports "run.json"
python surface_scope.py run --targets (Join-Path $docs "targets.json") --cloud-json (Join-Path $docs "aws_demo.json") --html-out $runHtml --json-out $runJson --timeout 1.5
if (!(Test-Path $runHtml)) { throw "Missing $runHtml" }
if (!(Test-Path $runJson)) { throw "Missing $runJson" }

# 4) Dry-run showcase (prints DRY-RUN line and writes nothing)
python surface_scope.py run --demo --json-out (Join-Path $reports "dry.json") --html-out (Join-Path $reports "dry.html") --no-write

Write-Host "`nDemo suite completed successfully." -ForegroundColor Green
