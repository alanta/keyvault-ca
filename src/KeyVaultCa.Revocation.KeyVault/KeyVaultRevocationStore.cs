using Azure;
using Azure.Security.KeyVault.Certificates;
using KeyVaultCa.Revocation.Interfaces;
using KeyVaultCa.Revocation.Models;
using Microsoft.Extensions.Logging;

namespace KeyVaultCa.Revocation.KeyVault;

/// <summary>
/// Key Vault-based implementation of IRevocationStore using certificate tags.
/// Stores revocation metadata directly on certificates as tags, eliminating the need for external storage.
/// </summary>
public class KeyVaultRevocationStore : IRevocationStore
{
    private readonly Func<Uri, CertificateClient> _certificateClientFactory;
    private readonly Uri? _keyVaultUri;
    private readonly ILogger<KeyVaultRevocationStore> _logger;

    public KeyVaultRevocationStore(
        Func<Uri, CertificateClient> certificateClientFactory,
        ILogger<KeyVaultRevocationStore> logger)
    {
        _certificateClientFactory = certificateClientFactory;
        _logger = logger;
    }
    
    public KeyVaultRevocationStore(
        Func<Uri, CertificateClient> certificateClientFactory,
        Uri  keyVaultUri,
        ILogger<KeyVaultRevocationStore> logger)
    {
        _certificateClientFactory = certificateClientFactory;
        _keyVaultUri = keyVaultUri;
        _logger = logger;
    }

    /// <summary>
    /// Adds revocation metadata to a certificate by updating its tags
    /// </summary>
    public async Task AddRevocationAsync(RevocationRecord record, CancellationToken ct = default)
    {
        _logger.LogInformation("Revoking certificate with serial number {Serial}", record.SerialNumber);

        // Find the certificate by serial number
        var certLocation = await FindCertificateBySerialNumberAsync(record.SerialNumber, ct);
        if (certLocation == null)
        {
            throw new InvalidOperationException($"Certificate with serial number {record.SerialNumber} not found in any configured Key Vault");
        }

        var client = _certificateClientFactory(certLocation.Value.KeyVaultUri);
        
        try
        {
            // Get current certificate properties
            var cert = await client.GetCertificateAsync(certLocation.Value.CertificateName, ct);
            var properties = cert.Value.Properties;

            // Add revocation tags
            properties.Tags["Revoked"] = "true";
            properties.Tags["RevokedDate"] = record.RevocationDate.ToString("o");
            properties.Tags["RevocationReason"] = ((int)record.Reason).ToString();
            properties.Tags["IssuerDN"] = record.IssuerDistinguishedName;
            
            if (!string.IsNullOrEmpty(record.Comments))
            {
                properties.Tags["RevocationComments"] = record.Comments;
            }

            // Update the certificate
            await client.UpdateCertificatePropertiesAsync(properties, ct);
            
            _logger.LogInformation("Certificate {Serial} revoked successfully in Key Vault {Vault}", 
                record.SerialNumber, certLocation.Value.KeyVaultUri);
        }
        catch (RequestFailedException ex)
        {
            _logger.LogError(ex, "Failed to revoke certificate {Serial}", record.SerialNumber);
            throw;
        }
    }

    /// <summary>
    /// Gets revocation information for a specific certificate by serial number
    /// </summary>
    public async Task<RevocationRecord?> GetRevocationAsync(string serialNumber, CancellationToken ct = default)
    {
        _logger.LogDebug("Looking up revocation status for serial number {Serial}", serialNumber);

        var certLocation = await FindCertificateBySerialNumberAsync(serialNumber, ct);
        if (certLocation == null)
        {
            _logger.LogDebug("Certificate with serial number {Serial} not found", serialNumber);
            return null;
        }

        var client = _certificateClientFactory(certLocation.Value.KeyVaultUri);
        var cert = await client.GetCertificateAsync(certLocation.Value.CertificateName, ct);
        
        return ParseRevocationFromTags(cert.Value.Properties.Tags, serialNumber);
    }

    /// <summary>
    /// Gets all revocations for a specific issuer by scanning all certificates
    /// </summary>
    public Task<IEnumerable<RevocationRecord>> GetRevocationsByIssuerAsync(
        string issuerDistinguishedName, 
        CancellationToken ct = default)
    {
        _logger.LogInformation("Scanning for revoked certificates issued by {Issuer}", issuerDistinguishedName);

        var revocations = new List<RevocationRecord>();

        // Note: This requires scanning multiple Key Vaults if configured
        // TODO: Support multiple Key Vaults via configuration
        if (_keyVaultUri == null)
        {
            throw new InvalidOperationException("KeyVault is not configured. Construct the store with a KeyVault URL.");
        }
        
        return GetRevocationsByIssuerAsync(_keyVaultUri, issuerDistinguishedName, ct);
    }

    /// <summary>
    /// Gets all revocations for a specific issuer from a specific Key Vault
    /// </summary>
    public async Task<IEnumerable<RevocationRecord>> GetRevocationsByIssuerAsync(
        Uri keyVaultUri,
        string issuerDistinguishedName,
        CancellationToken ct = default)
    {
        _logger.LogInformation("Scanning Key Vault {Vault} for revoked certificates issued by {Issuer}", 
            keyVaultUri, issuerDistinguishedName);

        var revocations = new List<RevocationRecord>();
        var client = _certificateClientFactory(keyVaultUri);

        await foreach (var certProperties in client.GetPropertiesOfCertificatesAsync())
        {
            // Only process enabled certificates
            if (certProperties.Enabled == false)
                continue;

            // Check if certificate is revoked
            if (!certProperties.Tags.TryGetValue("Revoked", out var revoked) || revoked != "true")
                continue;

            // Check if issuer matches (if IssuerDN tag exists)
            if (certProperties.Tags.TryGetValue("IssuerDN", out var issuerDN) && 
                !string.Equals(issuerDN, issuerDistinguishedName, StringComparison.OrdinalIgnoreCase))
                continue;

            // Get serial number from tags
            if (!certProperties.Tags.TryGetValue("SerialNumber", out var serialNumber))
            {
                _logger.LogWarning("Certificate {Name} is revoked but missing SerialNumber tag", certProperties.Name);
                continue;
            }

            var record = ParseRevocationFromTags(certProperties.Tags, serialNumber);
            if (record != null)
            {
                revocations.Add(record);
            }
        }

        _logger.LogInformation("Found {Count} revoked certificates for issuer {Issuer}", 
            revocations.Count, issuerDistinguishedName);

        return revocations;
    }

    /// <summary>
    /// Finds a certificate by serial number across configured Key Vaults.
    /// Returns the Key Vault URI and certificate name if found.
    /// </summary>
    private async Task<(Uri KeyVaultUri, string CertificateName)?> FindCertificateBySerialNumberAsync(
        string serialNumber,
        CancellationToken ct)
    {
        // TODO: Support multiple Key Vaults via configuration
        // For now, this needs to be enhanced to search across multiple vaults
        if (_keyVaultUri == null)
        {
            throw new InvalidOperationException("KeyVault is not configured. Construct the store with a KeyVault URL.");
        }

        var result = await FindCertificateBySerialNumberAsync(_keyVaultUri, serialNumber, ct);

        return result != null ? (_keyVaultUri, result) : null;
    }

    /// <summary>
    /// Finds a certificate by serial number in a specific Key Vault
    /// </summary>
    public async Task<string?> FindCertificateBySerialNumberAsync(
        Uri keyVaultUri,
        string serialNumber,
        CancellationToken ct = default)
    {
        _logger.LogDebug("Searching Key Vault {Vault} for certificate with serial {Serial}", 
            keyVaultUri, serialNumber);

        var client = _certificateClientFactory(keyVaultUri);

        await foreach (var certProperties in client.GetPropertiesOfCertificatesAsync())
        {
            if (certProperties.Tags.TryGetValue("SerialNumber", out var certSerial) &&
                string.Equals(certSerial, serialNumber, StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogDebug("Found certificate {Name} with serial {Serial}", 
                    certProperties.Name, serialNumber);
                return certProperties.Name;
            }
        }

        _logger.LogDebug("Certificate with serial {Serial} not found in Key Vault {Vault}", 
            serialNumber, keyVaultUri);
        return null;
    }

    /// <summary>
    /// Parses revocation information from certificate tags
    /// </summary>
    private RevocationRecord? ParseRevocationFromTags(IDictionary<string, string> tags, string serialNumber)
    {
        if (!tags.TryGetValue("Revoked", out var revoked) || revoked != "true")
            return null;

        if (!tags.TryGetValue("RevokedDate", out var revokedDateStr) ||
            !DateTimeOffset.TryParse(revokedDateStr, out var revokedDate))
        {
            _logger.LogWarning("Certificate {Serial} has invalid RevokedDate tag", serialNumber);
            return null;
        }

        var reason = RevocationReason.Unspecified;
        if (tags.TryGetValue("RevocationReason", out var reasonStr) &&
            int.TryParse(reasonStr, out var reasonInt))
        {
            reason = (RevocationReason)reasonInt;
        }

        tags.TryGetValue("IssuerDN", out var issuerDN);
        tags.TryGetValue("RevocationComments", out var comments);

        return new RevocationRecord
        {
            SerialNumber = serialNumber,
            RevocationDate = revokedDate,
            Reason = reason,
            IssuerDistinguishedName = issuerDN ?? string.Empty,
            Comments = comments
        };
    }
}
