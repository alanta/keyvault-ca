resourceGroup="rg-ca-test"
location="westeurope"
caKeyVault="kv-ca-test-99"
certificatesKeyVault="kv-issue-test-99"

USER_ID=$(az ad signed-in-user show --query id -o tsv)
if [ $? -ne 0 ]; then
    echo "Please login to Azure CLI, run: az login"
    exit 1
fi

# Create a resource group
az group create -n $resourceGroup -l $location
if [ $? -ne 0 ]; then
    echo "Failed to create resource group for Key Vaults"
    exit 1
fi

#CA_ID=$(az keyvault show -n $caKeyVault -g $resourceGroup --query id -o tsv)

CA_ID=$(az keyvault create -n $caKeyVault -g $resourceGroup -l $location --sku standard --enable-rbac-authorization true --query id -o tsv)
if [ $? -ne 0 ]; then
    echo "Failed to create Key Vault for CA"
    exit 1
fi

#CERTIFICATES_ID=$(az keyvault show -n $certificatesKeyVault -g $resourceGroup --query id -o tsv)

CERTIFICATES_ID=$(az keyvault create -n $certificatesKeyVault -g $resourceGroup -l $location --sku standard --enable-rbac-authorization true --query id -o tsv)
if [ $? -ne 0 ]; then
    echo "Failed to create Key Vault for issued certificates"
    exit 1
fi

# Assign RBAC permissions

# Assign KeyVault Secret User role to the current user for both Key Vaults
az role assignment create --role "Key Vault Secrets User" --assignee $USER_ID --scope "$CA_ID"
az role assignment create --role "Key Vault Secrets User" --assignee $USER_ID --scope "$CERTIFICATES_ID"

# Assign KeyVault Certificate Officer role to the current user for both Key Vaults
az role assignment create --role "Key Vault Certificates Officer" --assignee $USER_ID --scope "$CA_ID"
az role assignment create --role "Key Vault Certificates Officer" --assignee $USER_ID --scope "$CERTIFICATES_ID"

# Assign KeyVault Crypto User role to the current user for both Key Vaults
az role assignment create --role "Key Vault Crypto User" --assignee $USER_ID --scope "$CA_ID"
az role assignment create --role "Key Vault Crypto User" --assignee $USER_ID --scope "$CERTIFICATES_ID"