using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using KeyVaultCa.Revocation.Interfaces;
using KeyVaultCa.Revocation.Models;
using Microsoft.Extensions.Caching.Hybrid;
using Microsoft.Extensions.Logging;

namespace KeyVaultCa.Revocation;

/// <summary>
/// Decorator that adds hybrid caching to any IRevocationStore implementation.
/// Caches revocation lookups by serial number with stampede protection.
/// </summary>
public class CachedRevocationStore : IRevocationStore
{
    private static readonly TimeSpan CacheDuration = TimeSpan.FromMinutes(10);
    private readonly IRevocationStore _innerStore;
    private readonly HybridCache _cache;
    private readonly ILogger<CachedRevocationStore> _logger;

    /// <summary>
    /// Creates a caching decorator around an existing revocation store.
    /// </summary>
    /// <param name="innerStore">The underlying revocation store to wrap.</param>
    /// <param name="cache">Hybrid cache for storing lookup results.</param>
    /// <param name="logger">Logger for cache diagnostics.</param>
    public CachedRevocationStore(
        IRevocationStore innerStore,
        HybridCache cache,
        ILogger<CachedRevocationStore> logger)
    {
        ArgumentNullException.ThrowIfNull(innerStore);
        ArgumentNullException.ThrowIfNull(cache);
        ArgumentNullException.ThrowIfNull(logger);

        _innerStore = innerStore;
        _cache = cache;
        _logger = logger;

        _logger.LogInformation(
            "HybridCache enabled for revocation store (TTL: {Minutes} minutes)",
            CacheDuration.TotalMinutes);
    }

    /// <inheritdoc/>
    public async Task AddRevocationAsync(RevocationRecord record, CancellationToken ct = default)
    {
        await _innerStore.AddRevocationAsync(record, ct);

        // Invalidate cache entry for this serial number
        var cacheKey = GetCacheKey(record.SerialNumber);
        await _cache.RemoveAsync(cacheKey, ct);
        _logger.LogDebug("Invalidated cache entry for {SerialNumber}", record.SerialNumber);
    }

    /// <inheritdoc/>
    public async Task<RevocationRecord?> GetRevocationAsync(string serialNumber, CancellationToken ct = default)
    {
        var serialUpper = serialNumber.ToUpperInvariant();
        var cacheKey = GetCacheKey(serialUpper);

        // HybridCache provides automatic stampede protection and caching
        var record = await _cache.GetOrCreateAsync(
            cacheKey,
            async cancel =>
            {
                _logger.LogDebug("Cache miss for certificate {SerialNumber}", serialNumber);
                var result = await _innerStore.GetRevocationAsync(serialNumber, cancel);

                _logger.LogDebug(
                    "Cached {Status} status for {SerialNumber} (TTL: {Minutes} min)",
                    result != null ? "revoked" : "not revoked",
                    serialNumber,
                    CacheDuration.TotalMinutes);

                return result;
            },
            new HybridCacheEntryOptions
            {
                Expiration = CacheDuration,
                LocalCacheExpiration = CacheDuration
            },
            cancellationToken: ct);

        if (record != null)
        {
            _logger.LogDebug("Retrieved certificate {SerialNumber} from cache", serialNumber);
        }

        return record;
    }

    /// <inheritdoc/>
    public Task<IEnumerable<RevocationRecord>> GetRevocationsByIssuerAsync(
        string issuerDistinguishedName,
        CancellationToken ct = default)
    {
        // Don't cache this method - it's typically used for admin/bulk operations
        // where freshness is more important than performance
        return _innerStore.GetRevocationsByIssuerAsync(issuerDistinguishedName, ct);
    }

    private static string GetCacheKey(string serialNumber) => $"revocation:{serialNumber}";
}
