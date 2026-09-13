# WWFI installer for Windows (PowerShell).
#
# Usage (run as Administrator):
#   powershell -ExecutionPolicy Bypass -File scripts/install.ps1
#   powershell -ExecutionPolicy Bypass -File scripts/install.ps1 -Uninstall
#
# What it does (all reversible):
#   1. creates .venv and installs WWFI in editable mode
#   2. maps WWFI domains (demo.local, shop.local, cofeu.org -> 127.0.0.1) in %windir%\System32\drivers\etc\hosts
#   3. generates certs/ca.crt + certificates\ca.key (WWFI Local Root CA) if missing
#   4. adds the WWFI CA to the Windows system Root store -> Edge/Chrome/IE trust all WWFI domains
# It never touches your DHCP, proxy or DNS servers.

param(
  [switch]$DryRun,
  [switch]$Uninstall,
  [string]$Domains = "demo.local,shop.local,cofeu.org"
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$Venv = Join-Path $Root '.venv'
$VenvPy = Join-Path $Venv 'Scripts\python.exe'
$HostsFile = "$env:windir\System32\drivers\etc\hosts"
$MarkerStart = '# === WWFI BEGIN ==='
$MarkerEnd = '# === WWFI END ==='

function Log($m) { Write-Host "[wwfi-install] $m" }

function Run($argumentList) {
  if ($DryRun) { Log "DRY-RUN: $argumentList"; return }
  & $argumentList
  if ($LASTEXITCODE -ne 0) { throw "command failed: $argumentList" }
}

$isAdmin = ([Security.Principal.WindowsPrincipal]`
  [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
  if ($DryRun) { Log "requires an elevated PowerShell; rerun-as-Administrator will be started" }
  else {
    Log "This installer needs an elevated PowerShell. Relaunching as Administrator..."
    $args = "-ExecutionPolicy Bypass -File `"$PSCommandPath`""
    if ($Uninstall) { $args += " -Uninstall" }
    if ($DryRun) { $args += " -DryRun" }
    Start-Process powershell -Verb RunAs -ArgumentList $args
  }
  exit 0
}

function Get-Py {
  $py = Get-Command py -ErrorAction SilentlyContinue
  if ($py) { return @('py', '-3') }
  $py = Get-Command python -ErrorAction SilentlyContinue
  if ($py) { return @('python') }
  throw "Python 3 not found. Install from https://python.org and retry."
}

function New-VenvAndInstall {
  Log "Preparing WWFI installation in $Root"
  $py = Get-Py
  if (-not (Test-Path $Venv)) {
    Log "Creating Python virtual environment"
    Run (@($py) + @('-m', 'venv', $Venv))
  }
  Log "Installing WWFI in editable mode"
  & $VenvPy -m pip install --upgrade pip setuptools wheel
  if ($LASTEXITCODE -ne 0) { throw "pip tooling upgrade failed" }
  & $VenvPy -m pip install -e $Root
  if ($LASTEXITCODE -ne 0) { throw "WWFI editable install failed" }
}

function Ensure-CA {
  if (-not (Test-Path (Join-Path $Root 'certs\ca.crt')) -or
      -not (Test-Path (Join-Path $Root 'certs\ca.key'))) {
    Log "Generating WWFI Local Root CA in certs/"
    New-Item -ItemType Directory -Force -Path (Join-Path $Root 'certs') | Out-Null
    $code = @'
import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
now = datetime.datetime.now(datetime.timezone.utc)
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "WWFI Local Root CA")])
cert = (
    x509.CertificateBuilder()
    .subject_name(name)
    .issuer_name(name)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - datetime.timedelta(days=1))
    .not_valid_after(now + datetime.timedelta(days=3650))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
        key_encipherment=False, data_encipherment=False, key_agreement=False,
        key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False),
        critical=True)
    .sign(key, hashes.SHA256())
)
open(r"REPLACE_ROOT\certs\ca.key", "wb").write(
    key.private_bytes(serialization.Encoding.PEM,
                      serialization.PrivateFormat.TraditionalOpenSSL,
                      serialization.NoEncryption()))
open(r"REPLACE_ROOT\certs\ca.crt", "wb").write(
    cert.public_bytes(serialization.Encoding.PEM))
'@
    $script = $code.Replace('REPLACE_ROOT', $Root)
    Push-Location $Root
    try { $script | & $VenvPy - }
    finally { Pop-Location }
    if ($LASTEXITCODE -ne 0) { throw "CA generation failed" }
  }
}

function Set-HostsBlock {
  $lines = $Domains -split ',' | ForEach-Object { "127.0.0.1   $($_.Trim())" }
  $block = $MarkerStart + "`r`n" + ($lines -join "`r`n") + "`r`n" + $MarkerEnd
  $content = if (Test-Path $HostsFile) { Get-Content -Raw $HostsFile } else { '' }
  if ($DryRun) { Log "DRY-RUN: write hosts block:`n$block"; return }
  Log "Mapping WWFI domains in $HostsFile"
  $backup = "$HostsFile.wwfi.bak"
  if (-not (Test-Path $backup)) { Copy-Item $HostsFile $backup }
  if ($content -match [regex]::Escape($MarkerStart)) {
    $content = $content -replace "(?s)$([regex]::Escape($MarkerStart)).*?$([regex]::Escape($MarkerEnd))", $block
  } elseif ($content.Trim() -and -not $content.EndsWith("`r`n")) {
    $content += "`r`n"
    $content += $block
  } else {
    $content += $block + "`r`n"
  }
  Set-Content -Path $HostsFile -Value $content -Encoding ascii
}

function Remove-HostsBlock {
  Log "Removing WWFI block from $HostsFile"
  $content = if (Test-Path $HostsFile) { Get-Content -Raw $HostsFile } else { return }
  if ($content -match [regex]::Escape($MarkerStart)) {
    $content = $content -replace "(?s)^\s*$([regex]::Escape($MarkerStart)).*?$([regex]::Escape($MarkerEnd))\s*`r?`n?", ''
    Set-Content -Path $HostsFile -Value $content -Encoding ascii
    Log "hosts block removed (backup kept at $HostsFile.wwfi.bak)"
  }
}

function Add-Trust {
  if ($DryRun) { Log "DRY-RUN: certutil -f -addstore Root certs\ca.crt"; return }
  Log "Installing WWFI Local Root CA into Windows system Root store"
  certutil -f -addstore "Root" (Join-Path $Root 'certs\ca.crt')
  if ($LASTEXITCODE -eq 0) { Log "Trust installed -> Edge / Chrome / IE trust all WWFI-signed domains" }
  else { Log "certutil failed with code $LASTEXITCODE"; throw "certutil failed" }
  Log "Firefox keeps its own store: import certs\ca.crt once, or set security.enterprise_roots=true in about:config."
}

function Remove-Trust {
  if ($DryRun) { Log "DRY-RUN: certutil -delstore Root WWFI Local Root CA"; return }
  Log "Removing WWFI Local Root CA from Root store (best effort)"
  certutil -delstore "Root" "WWFI Local Root CA" 2>$null
  if (-not $DryRun) { Log "Done (exit code $LASTEXITCODE)" }
}

Log "WWFI installer (Windows) starting..."

if ($Uninstall) {
  Remove-HostsBlock
  Remove-Trust
  Log "WWFI removed from hosts + Root store. venv left at $Venv (delete manually if wanted)."
  exit 0
}

New-VenvAndInstall
Ensure-CA
Set-HostsBlock
Add-Trust

Log "WWFI install complete"
Log "Run:  $VenvPy scripts\dashboard_server.py --port 8087"
Log "Test:  .venv\Scripts\python.exe -m pytest -q"
Log "For a real local DNS server on Windows use WSL (run scripts/install.sh) or a DNS proxy (e.g. Acrylic)."