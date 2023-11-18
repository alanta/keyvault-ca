$ErrorActionPreference = "Stop"

$caName = "MyLocalDomain"
$dns = "mycompany.local"
$provisioner = "MyCompany"
$keyvault = "mykeyvault"
$rootKey="root-key"
$internmediateKey="intermediate-key"

Write-Host -ForegroundColor Yellow "Enter the name of the keyvault to use (default $keyvault)" -NoNewline
$userInput = Read-Host

if( $userInput -ne "" ) {
    $keyvault = $userInput
}

$kvInfo=$(az keyvault show --name $keyvault --query id --output tsv)

if( $LASTEXITCODE -ne 0 ) {
    Write-Host -ForegroundColor Red "Keyvault $keyvault not found. Make sure Azure CLI is logged in and the keyvault exists."
    exit
}

$keyUrl=$(az keyvault key show --vault-name $keyvault --name $rootKey --query key.kid --output TSV)

if( $LASTEXITCODE -eq 0 ) {
    Write-Host -ForegroundColor Red "Keyvault $keyvault already contains a key named $rootKey. Please use a different key name or a different Key Vault."
    exit
}

Write-Host -ForegroundColor Yellow "Enter the nameof the Certificate Authority (default $caName)" -NoNewline
$userInput = Read-Host

if( $userInput -ne "" ) {
    $caName = $userInput
}

Write-Host -ForegroundColor Yellow "Enter the DNS name of the Certificate Authority (default $dns)" -NoNewline
$userInput = Read-Host

if( $userInput -ne "" ) {
    $dns = $userInput
}

Write-Host -ForegroundColor Yellow "Enter the name of the provisioner (default $provisioner)" -NoNewline
$userInput = Read-Host

if( $userInput -ne "" ) {
    $provisioner = $userInput
}

$ENV:STEPPATH="$PWD/ca"

# create the ca directory if it doesn't exist
if( -not (Test-Path $PWD/ca) ) {
    mkdir $PWD/ca
}
step ca init --kms=azurekms --kms-root="azurekms:name=$rootKey;vault=$keyvault" --kms-intermediate="azurekms:name=$internmediateKey;vault=$keyvault" --deployment-type standalone --name $caName --dns $dns --provisioner "$provisioner"