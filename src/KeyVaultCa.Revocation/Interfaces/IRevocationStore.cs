using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using KeyVaultCa.Revocation.Models;

namespace KeyVaultCa.Revocation.Interfaces;

/// <summary>
/// Interface for storing and retrieving certificate revocation information
/// </summary>
public interface IRevocationStore
{
    /// <summary>
    /// Add a certificate revocation record
    /// </summary>
    /// <param name="record">The revocation record to add</param>
    /// <param name="ct">Cancellation token</param>
    Task AddRevocationAsync(RevocationRecord record, CancellationToken ct = default);

    /// <summary>
    /// Get revocation information for a specific certificate serial number
    /// </summary>
    /// <param name="serialNumber">The certificate serial number (hex format, uppercase)</param>
    /// <param name="ct">Cancellation token</param>
    /// <returns>The revocation record if found, null otherwise</returns>
    Task<RevocationRecord?> GetRevocationAsync(string serialNumber, CancellationToken ct = default);

    /// <summary>
    /// Get all revocations for a specific issuer
    /// </summary>
    /// <param name="issuerDistinguishedName">The issuer's Distinguished Name</param>
    /// <param name="ct">Cancellation token</param>
    /// <returns>Collection of revocation records</returns>
    Task<IEnumerable<RevocationRecord>> GetRevocationsByIssuerAsync(string issuerDistinguishedName, CancellationToken ct = default);
}
