using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Azure.Data.Tables;
using KeyVaultCa.Revocation.Interfaces;
using KeyVaultCa.Revocation.Models;
using Microsoft.Extensions.Logging;

namespace KeyVaultCa.Revocation.TableStorage;

/// <summary>
/// Azure Table Storage implementation of IRevocationStore
/// </summary>
public class TableStorageRevocationStore : IRevocationStore
{
    private const string TableName = "CertificateRevocations";
    private readonly TableClient _tableClient;
    private readonly ILogger<TableStorageRevocationStore> _logger;

    /// <summary>
    /// Initialize the Table Storage revocation store
    /// </summary>
    /// <param name="connectionString">Azure Storage connection string</param>
    /// <param name="loggerFactory">Logger factory</param>
    public TableStorageRevocationStore(string connectionString, ILoggerFactory loggerFactory)
    {
        ArgumentNullException.ThrowIfNull(connectionString);
        ArgumentNullException.ThrowIfNull(loggerFactory);

        _logger = loggerFactory.CreateLogger<TableStorageRevocationStore>();
        _tableClient = new TableClient(connectionString, TableName);

        // Ensure table exists
        _tableClient.CreateIfNotExists();
    }

    /// <summary>
    /// Initialize with an existing TableClient (for testing)
    /// </summary>
    public TableStorageRevocationStore(TableClient tableClient, ILoggerFactory loggerFactory)
    {
        ArgumentNullException.ThrowIfNull(tableClient);
        ArgumentNullException.ThrowIfNull(loggerFactory);

        _tableClient = tableClient;
        _logger = loggerFactory.CreateLogger<TableStorageRevocationStore>();
    }

    /// <inheritdoc/>
    public async Task AddRevocationAsync(RevocationRecord record, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(record);

        var entity = RevocationTableEntity.FromRecord(record);

        _logger.LogInformation("Adding revocation for certificate {SerialNumber}", record.SerialNumber);

        await _tableClient.UpsertEntityAsync(entity, cancellationToken: ct);

        _logger.LogInformation("Successfully added revocation for certificate {SerialNumber}", record.SerialNumber);
    }

    /// <inheritdoc/>
    public async Task<RevocationRecord?> GetRevocationAsync(string serialNumber, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(serialNumber);

        var serialUpper = serialNumber.ToUpperInvariant();
        var partitionKey = serialUpper.Length >= 2 ? serialUpper.Substring(0, 2) : serialUpper;

        _logger.LogDebug("Looking up revocation for certificate {SerialNumber}", serialNumber);

        try
        {
            var response = await _tableClient.GetEntityAsync<RevocationTableEntity>(
                partitionKey,
                serialUpper,
                cancellationToken: ct);

            var record = response.Value.ToRecord();
            _logger.LogDebug("Found revocation for certificate {SerialNumber}", serialNumber);
            return record;
        }
        catch (Azure.RequestFailedException ex) when (ex.Status == 404)
        {
            _logger.LogDebug("No revocation found for certificate {SerialNumber}", serialNumber);
            return null;
        }
    }

    /// <inheritdoc/>
    public async Task<IEnumerable<RevocationRecord>> GetRevocationsByIssuerAsync(
        string issuerDistinguishedName,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(issuerDistinguishedName);

        _logger.LogInformation("Querying revocations for issuer {IssuerDN}", issuerDistinguishedName);

        var filter = TableClient.CreateQueryFilter($"IssuerDistinguishedName eq {issuerDistinguishedName}");
        var results = new List<RevocationRecord>();

        await foreach (var entity in _tableClient.QueryAsync<RevocationTableEntity>(filter, cancellationToken: ct))
        {
            results.Add(entity.ToRecord());
        }

        _logger.LogInformation("Found {Count} revocations for issuer {IssuerDN}",
            results.Count, issuerDistinguishedName);

        return results;
    }
}
