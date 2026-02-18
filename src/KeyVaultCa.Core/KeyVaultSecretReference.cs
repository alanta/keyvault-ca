using System;

namespace KeyVaultCa.Core;

public class KeyVaultSecretReference
{
    public KeyVaultSecretReference(Uri keyVaultUrl, string secretName)
    {
        SecretName = secretName;
        KeyVaultUrl = keyVaultUrl;
    }

    /// <summary>
    /// Parses a Key Vault secret reference from a string.
    /// </summary>
    /// <param name="secretReference">The string representation of the Key Vault secret reference to parse.</param>
    /// <param name="result">When this method returns, contains the parsed <see cref="KeyVaultSecretReference"/> if successful, or <c>null</c> if parsing failed.</param>
    /// <returns>
    /// true if the secret reference was successfully parsed; otherwise, false.
    /// </returns>
    public static bool TryParse(string secretReference, out KeyVaultSecretReference? result)
    {
        if (string.IsNullOrWhiteSpace(secretReference))
        {
            result = null;
            return false;
        }
        
        // secretReference can either be a full URI, or secretname@keyvaultname
        // first test for the presence of @
        if (secretReference.Contains('@'))
        {
            var parts = secretReference.Split('@', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 2)
            {

                result = FromNames(parts[1], parts[0]);
                return true;
            }
        }
        
        if (Uri.TryCreate(secretReference, UriKind.Absolute, out var uri))
        {
            try
            {
                result = FromUri(uri);
                return true;
            }
            catch (ArgumentException)
            {
                // If the URI is not a valid Key Vault secret URI, we return false
                // This is to handle cases where the URI does not match the expected format
            }
        }

        result = null;
        return false;
    }
    
    /// <summary>
    /// Parses a Key Vault secret reference from a full KeyVault URI.
    /// </summary>
    /// <param name="secretUri">The uri of a key vault secret. Expected format is https://myvault.vault.azure.net/secrets/mysecret</param>
    /// <returns>A keyvault secret reference.</returns>
    /// <exception cref="ArgumentNullException">Null is passed in.</exception>
    /// <exception cref="ArgumentException">An invalid url is provided.</exception>
    public static KeyVaultSecretReference FromUri(Uri secretUri)
    {
        if (secretUri == null) throw new ArgumentNullException(nameof(secretUri));
        
        var segments = secretUri.AbsolutePath.Trim('/').Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length < 2 || !(string.Equals(segments[0], "secrets", StringComparison.OrdinalIgnoreCase) 
                                     || string.Equals(segments[0], "certificates", StringComparison.OrdinalIgnoreCase)))
            throw new ArgumentException("Invalid Key Vault secret URI format.", nameof(secretUri));
        
        var keyVaultUrl = new Uri($"{secretUri.Scheme}://{secretUri.Host}/");
        var secretName = segments[1];

        return new KeyVaultSecretReference(keyVaultUrl, secretName);
    
    }
    
    /// <summary>
    /// Creates a new instance of <see cref="KeyVaultSecretReference"/> using the Key Vault name and secret name.
    /// </summary>
    /// <returns>A KeyVaultSecretReference instance.</returns>
    /// <param name="secretName">The name of the secret.</param>
    /// <returns></returns>
    public static KeyVaultSecretReference FromNames(string keyVaultName, string secretName)
    {
        return new KeyVaultSecretReference(KeyVaultUrlFromName(keyVaultName), secretName);
    }
    
    /// <summary>
    /// <param name="keyVaultName">The name of the Azure Key Vault.</param>
    /// <returns>The full URI of the Azure Key Vault.</returns>
    /// <param name="keyVaultName"></param>
    /// <returns></returns>
    /// <exception cref="ArgumentException"></exception>
    public static Uri KeyVaultUrlFromName(string keyVaultName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyVaultName);
        
        if(keyVaultName.StartsWith("https://", StringComparison.OrdinalIgnoreCase) )
        {
            // If the name already contains a full URL, just return it as a URI
            return new Uri(keyVaultName);
        }
        
        // Azure Key Vault name rules: 3-24 chars, alphanumeric, only lowercase letters and digits
        if (keyVaultName.Length < 3 || keyVaultName.Length > 24 ||
            !System.Text.RegularExpressions.Regex.IsMatch(keyVaultName, "^[a-z][a-z0-9\\-]+[a-z0-9]+$"))
        {
            throw new ArgumentException("Azure Key Vault name must be 3-24 characters, only lowercase letters and digits.", nameof(keyVaultName));
        }
    
        return new Uri($"https://{keyVaultName}.vault.azure.net/");
    }

    /// <summary>
    /// Returns true if <paramref name="name"/> is a valid Azure Key Vault certificate/secret name:
    /// 1–127 characters, must start with a letter, and contain only letters, digits, and hyphens.
    /// </summary>
    public static bool IsValidCertificateName(string? name)
    {
        if (string.IsNullOrEmpty(name)) return false;
        return System.Text.RegularExpressions.Regex.IsMatch(name, @"^[a-zA-Z][a-zA-Z0-9\-]{0,126}$");
    }

    /// <summary>
    /// The name of the Key Vault secret.
    /// </summary>
    public string SecretName { get; private init; }

    /// <summary>
    /// The full URL of the Key Vault where the secret is stored.
    /// </summary>
    public Uri KeyVaultUrl { get; private init; }
    
    public Uri SecretUri => new Uri($"{KeyVaultUrl}secrets/{SecretName}");
    public Uri CertificateUri => new Uri($"{KeyVaultUrl}certificates/{SecretName}");
}