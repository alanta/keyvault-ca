using System;
using KeyVaultCa.Revocation.Interfaces;
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

        services.AddSingleton<IRevocationStore>(sp =>
            new TableStorageRevocationStore(
                connectionString,
                sp.GetRequiredService<ILoggerFactory>()));

        return services;
    }
}
