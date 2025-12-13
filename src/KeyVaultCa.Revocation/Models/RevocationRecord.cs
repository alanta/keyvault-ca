using System;

namespace KeyVaultCa.Revocation.Models;

/// <summary>
/// Represents a revoked certificate record
/// </summary>
public class RevocationRecord
{
    /// <summary>
    /// The certificate serial number in hexadecimal format (uppercase)
    /// </summary>
    public required string SerialNumber { get; set; }

    /// <summary>
    /// The date and time when the certificate was revoked
    /// </summary>
    public required DateTimeOffset RevocationDate { get; set; }

    /// <summary>
    /// The reason for revocation
    /// </summary>
    public required RevocationReason Reason { get; set; }

    /// <summary>
    /// The Distinguished Name of the issuer CA
    /// </summary>
    public required string IssuerDistinguishedName { get; set; }

    /// <summary>
    /// Optional comments about the revocation
    /// </summary>
    public string? Comments { get; set; }
}
