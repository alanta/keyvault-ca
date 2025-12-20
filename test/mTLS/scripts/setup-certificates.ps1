#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Sets up all certificates required for the mTLS test using Azure Key Vault.

.DESCRIPTION
    This script creates the following certificates in Azure Key Vault:
    1. Root CA certificate
    2. OCSP Signing certificate (with --ocsp-signing flag)
    3. API Server certificate (with OCSP URL in AIA extension)
    4. API Client certificate (with OCSP URL in AIA extension)

    Then downloads all certificates to the ./certs directory for use by the test applications.

.PARAMETER KeyVaultName
    The name of the Azure Key Vault to use (without .vault.azure.net suffix)

.EXAMPLE
    ./setup-certificates.ps1 -KeyVaultName "my-ca-vault"
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$KeyVaultName
)

$ErrorActionPreference = "Stop"

# Configuration
$KeyVaultUrl = "https://$KeyVaultName.vault.azure.net"
$OcspUrl = "http://ocsp.localhost:5000"
$CliPath = "../../../src/KeyVaultCa.Cli/bin/Debug/net8.0/KeyVaultCa.Cli"
$CertsDir = "../certs"

Write-Host "================================" -ForegroundColor Cyan
Write-Host "KeyVault CA Certificate Setup" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Key Vault: $KeyVaultUrl" -ForegroundColor Yellow
Write-Host "OCSP URL: $OcspUrl" -ForegroundColor Yellow
Write-Host ""

# Check if CLI exists
if (!(Test-Path $CliPath)) {
    Write-Host "❌ CLI tool not found at: $CliPath" -ForegroundColor Red
    Write-Host "Please build the CLI first:" -ForegroundColor Yellow
    Write-Host "  dotnet build ../../../src/KeyVaultCa.Cli/KeyVaultCa.Cli.csproj" -ForegroundColor Yellow
    exit 1
}

# Create certs directory
if (!(Test-Path $CertsDir)) {
    New-Item -ItemType Directory -Path $CertsDir | Out-Null
    Write-Host "✅ Created certificates directory: $CertsDir" -ForegroundColor Green
}

# Step 1: Create Root CA
Write-Host ""
Write-Host "Step 1: Creating Root CA certificate..." -ForegroundColor Cyan
& $CliPath create-ca-cert `
    -kv $KeyVaultName `
    -cn "CN=mTLS Test Root CA, O=Test, C=NL" `
    --duration 730 `
    root-ca

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Failed to create Root CA" -ForegroundColor Red
    exit 1
}
Write-Host "✅ Root CA created successfully" -ForegroundColor Green

# Step 2: Create OCSP Signing Certificate
Write-Host ""
Write-Host "Step 2: Creating OCSP Signing certificate..." -ForegroundColor Cyan
& $CliPath issue-cert `
    -kv $KeyVaultName `
    root-ca `
    ocsp-signer `
    -d ocsp.localhost `
    --duration 365 `
    --ocsp-signing

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Failed to create OCSP Signing certificate" -ForegroundColor Red
    exit 1
}
Write-Host "✅ OCSP Signing certificate created successfully" -ForegroundColor Green

# Step 3: Create API Server Certificate
Write-Host ""
Write-Host "Step 3: Creating API Server certificate..." -ForegroundColor Cyan
& $CliPath issue-cert `
    -kv $KeyVaultName `
    root-ca `
    api-server `
    --duration 365 `
    --ocsp-url $OcspUrl `
    --dns localhost `
    --dns api-server

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Failed to create API Server certificate" -ForegroundColor Red
    exit 1
}
Write-Host "✅ API Server certificate created successfully" -ForegroundColor Green

# Step 4: Create API Client Certificate
Write-Host ""
Write-Host "Step 4: Creating API Client certificate..." -ForegroundColor Cyan
& $CliPath issue-cert `
    -kv $KeyVaultName `
    root-ca `
    api-client `
    -d api-client `
    --duration 365 `
    --ocsp-url $OcspUrl

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Failed to create API Client certificate" -ForegroundColor Red
    exit 1
}
Write-Host "✅ API Client certificate created successfully" -ForegroundColor Green

# Step 5: Download Certificates
Write-Host ""
Write-Host "Step 5: Downloading certificates..." -ForegroundColor Cyan

# Download Root CA
Write-Host "  Downloading root-ca..." -ForegroundColor Gray
& $CliPath download-cert -kv $KeyVaultName root-ca
if ($LASTEXITCODE -ne 0) { Write-Host "❌ Failed to download root-ca" -ForegroundColor Red; exit 1 }
Move-Item -Force "root-ca.crt" "$CertsDir/root-ca.crt"

# Download OCSP Signer
Write-Host "  Downloading ocsp-signer..." -ForegroundColor Gray
& $CliPath download-cert -kv $KeyVaultName -k ocsp-signer
if ($LASTEXITCODE -ne 0) { Write-Host "❌ Failed to download ocsp-signer" -ForegroundColor Red; exit 1 }
Move-Item -Force "ocsp-signer.crt" "$CertsDir/ocsp-signer.crt"
Move-Item -Force "ocsp-signer.pfx" "$CertsDir/ocsp-signer.pfx"

# Download API Server
Write-Host "  Downloading api-server..." -ForegroundColor Gray
& $CliPath download-cert -kv $KeyVaultName -k api-server
if ($LASTEXITCODE -ne 0) { Write-Host "❌ Failed to download api-server" -ForegroundColor Red; exit 1 }
Move-Item -Force "api-server.crt" "$CertsDir/api-server.crt"
Move-Item -Force "api-server.pfx" "$CertsDir/api-server.pfx"

# Download API Client
Write-Host "  Downloading api-client..." -ForegroundColor Gray
& $CliPath download-cert -kv $KeyVaultName -k api-client
if ($LASTEXITCODE -ne 0) { Write-Host "❌ Failed to download api-client" -ForegroundColor Red; exit 1 }
Move-Item -Force "api-client.crt" "$CertsDir/api-client.crt"
Move-Item -Force "api-client.pfx" "$CertsDir/api-client.pfx"

Write-Host "✅ All certificates downloaded to $CertsDir" -ForegroundColor Green

# Step 6: Verify OCSP URL in certificates
Write-Host ""
Write-Host "Step 6: Verifying OCSP URL in certificates..." -ForegroundColor Cyan

if (Get-Command openssl -ErrorAction SilentlyContinue) {
    Write-Host "  API Server certificate AIA extension:" -ForegroundColor Gray
    openssl x509 -in "$CertsDir/api-server.crt" -text -noout | Select-String -Pattern "OCSP - URI" -Context 0,1

    Write-Host "  API Client certificate AIA extension:" -ForegroundColor Gray
    openssl x509 -in "$CertsDir/api-client.crt" -text -noout | Select-String -Pattern "OCSP - URI" -Context 0,1
} else {
    Write-Host "  ⚠️  OpenSSL not found, skipping certificate verification" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "================================" -ForegroundColor Green
Write-Host "✅ Certificate setup complete!" -ForegroundColor Green
Write-Host "================================" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "1. Update OcspResponder/appsettings.json with KeyVault URL:" -ForegroundColor Yellow
Write-Host "   ""KeyVault:Url"": ""$KeyVaultUrl""" -ForegroundColor Gray
Write-Host ""
Write-Host "2. Start the Aspire AppHost:" -ForegroundColor Yellow
Write-Host "   cd ../AppHost" -ForegroundColor Gray
Write-Host "   dotnet run" -ForegroundColor Gray
Write-Host ""
