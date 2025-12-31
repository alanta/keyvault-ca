using System;
using KeyVaultCa.Revocation.Interfaces;
using Microsoft.Extensions.Caching.Hybrid;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace KeyVaultCa.Revocation.TableStorage;

/// <summary>
/// Extension methods for registering Azure Table Storage revocation store in the DI container.
/// </summary>
public static class TableStorageServiceCollectionExtensions
{
    /// <summary>
    /// Adds Azure Table Storage as the revocation store for certificate revocation data.
    /// Automatically wraps the store with a HybridCache decorator for improved performance
    /// with stampede protection.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="connectionString">Azure Table Storage connection string.</param>
    /// <returns>The service collection for chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown if connection string is null or empty.</exception>
    public static IServiceCollection AddTableStorageRevocationStore(
        this IServiceCollection services,
        string connectionString)
    {
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            throw new ArgumentNullException(nameof(connectionString),
                "Table Storage connection string is required");
        }

        // Add HybridCache for the caching decorator
        services.AddHybridCache();

        services.AddSingleton<IRevocationStore>(sp =>
        {
            // Create the underlying Table Storage store
            var tableStore = new TableStorageRevocationStore(
                connectionString,
                sp.GetRequiredService<ILoggerFactory>());

            // Wrap it with the caching decorator
            return new CachedRevocationStore(
                tableStore,
                sp.GetRequiredService<HybridCache>(),
                sp.GetRequiredService<ILogger<CachedRevocationStore>>());
        });

        return services;
    }
}
