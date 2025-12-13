using System;
using Azure;
using Azure.Data.Tables;
using KeyVaultCa.Revocation.Models;

namespace KeyVaultCa.Revocation.TableStorage;

/// <summary>
/// Azure Table Storage entity for certificate revocation records
/// </summary>
public class RevocationTableEntity : ITableEntity
{
    /// <summary>
    /// Partition key: First 2 characters of serial number (for distribution)
    /// </summary>
    public string PartitionKey { get; set; } = string.Empty;

    /// <summary>
    /// Row key: Full serial number (hex uppercase)
    /// </summary>
    public string RowKey { get; set; } = string.Empty;

    /// <summary>
    /// Entity timestamp (managed by Azure)
    /// </summary>
    public DateTimeOffset? Timestamp { get; set; }

    /// <summary>
    /// Entity ETag (managed by Azure)
    /// </summary>
    public ETag ETag { get; set; }

    /// <summary>
    /// Full serial number (hex uppercase) - redundant with RowKey but useful for queries
    /// </summary>
    public string SerialNumber { get; set; } = string.Empty;

    /// <summary>
    /// Revocation date/time
    /// </summary>
    public DateTimeOffset RevocationDate { get; set; }

    /// <summary>
    /// Revocation reason code (RFC 5280)
    /// </summary>
    public int RevocationReason { get; set; }

    /// <summary>
    /// Issuer Distinguished Name
    /// </summary>
    public string IssuerDistinguishedName { get; set; } = string.Empty;

    /// <summary>
    /// Optional comments
    /// </summary>
    public string? Comments { get; set; }

    /// <summary>
    /// Create entity from RevocationRecord
    /// </summary>
    public static RevocationTableEntity FromRecord(RevocationRecord record)
    {
        var serialUpper = record.SerialNumber.ToUpperInvariant();
        var partitionKey = serialUpper.Length >= 2 ? serialUpper.Substring(0, 2) : serialUpper;

        return new RevocationTableEntity
        {
            PartitionKey = partitionKey,
            RowKey = serialUpper,
            SerialNumber = serialUpper,
            RevocationDate = record.RevocationDate,
            RevocationReason = (int)record.Reason,
            IssuerDistinguishedName = record.IssuerDistinguishedName,
            Comments = record.Comments
        };
    }

    /// <summary>
    /// Convert entity to RevocationRecord
    /// </summary>
    public RevocationRecord ToRecord()
    {
        return new RevocationRecord
        {
            SerialNumber = SerialNumber,
            RevocationDate = RevocationDate,
            Reason = (Models.RevocationReason)RevocationReason,
            IssuerDistinguishedName = IssuerDistinguishedName,
            Comments = Comments
        };
    }
}
