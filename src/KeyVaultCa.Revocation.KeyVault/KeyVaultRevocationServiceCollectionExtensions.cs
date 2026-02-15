using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using KeyVaultCa.Revocation.Interfaces;
using Microsoft.Extensions.Caching.Hybrid;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace KeyVaultCa.Revocation.KeyVault;

/// <summary>
/// Extension methods for configuring Key Vault-based revocation store services
/// </summary>
public static class KeyVaultRevocationServiceCollectionExtensions
{
    /// <summary>
    /// Adds Key Vault-based revocation store with caching support.
    /// Revocation data is stored as certificate tags in Azure Key Vault.
    /// </summary>
    /// <param name="services">The service collection</param>
    /// <param name="keyVaultUri"></param>
    /// <returns>The service collection for chaining</returns>
    public static IServiceCollection AddKeyVaultRevocationStore(
        this IServiceCollection services, Uri keyVaultUri)
    {
        // Add HybridCache for optimal performance
        services.AddHybridCache(options =>
        {
            options.DefaultEntryOptions = new HybridCacheEntryOptions
            {
                Expiration = TimeSpan.FromMinutes(5),
                LocalCacheExpiration = TimeSpan.FromMinutes(1)
            };
        });

        // Register the revocation store with caching wrapper
        services.AddSingleton<IRevocationStore>(sp =>
        {
            var credential = new DefaultAzureCredential(new DefaultAzureCredentialOptions
            {
                ExcludeEnvironmentCredential = false,
                ExcludeManagedIdentityCredential = false,
                ExcludeVisualStudioCredential = false,
                ExcludeVisualStudioCodeCredential = false,
                ExcludeAzureCliCredential = false,
                ExcludeAzurePowerShellCredential = false,
                ExcludeInteractiveBrowserCredential = true
            });
            
            var clientCache = new Dictionary<Uri, CertificateClient>();

            var certificateClientFactory = (Uri uri) =>
            {
                if (!clientCache.TryGetValue(uri, out var client))
                {
                    lock (clientCache)
                    {
                        if (!clientCache.TryGetValue(uri, out client))
                        {
                            client = new CertificateClient(uri, credential);
                            clientCache.Add(uri, client);        
                        }
                    }
                }

                return client;
            };
            
            var logger = sp.GetRequiredService<ILogger<KeyVaultRevocationStore>>();
            var cache = sp.GetRequiredService<HybridCache>();

            var store = new KeyVaultRevocationStore(certificateClientFactory, keyVaultUri, logger);
            return new CachedRevocationStore(store, cache, sp.GetRequiredService<ILogger<CachedRevocationStore>>());
        });

        return services;
    }

    /// <summary>
    /// Adds Key Vault-based revocation store with custom credential.
    /// Revocation data is stored as certificate tags in Azure Key Vault.
    /// </summary>
    /// <param name="services">The service collection</param>
    /// <param name="certificateClientFactory">Factory function for creating CertificateClient instances</param>
    /// <returns>The service collection for chaining</returns>
    public static IServiceCollection AddKeyVaultRevocationStore(
        this IServiceCollection services,
        Func<Uri, CertificateClient> certificateClientFactory)
    {
        // Add HybridCache for optimal performance
        services.AddHybridCache(options =>
        {
            options.DefaultEntryOptions = new HybridCacheEntryOptions
            {
                Expiration = TimeSpan.FromMinutes(5),
                LocalCacheExpiration = TimeSpan.FromMinutes(1)
            };
        });

        // Register the factory
        services.AddSingleton(certificateClientFactory);

        // Register the revocation store with caching wrapper
        services.AddSingleton<IRevocationStore>(sp =>
        {
            var logger = sp.GetRequiredService<ILogger<KeyVaultRevocationStore>>();
            var cache = sp.GetRequiredService<HybridCache>();

            var store = new KeyVaultRevocationStore(certificateClientFactory, logger);
            return new CachedRevocationStore(store, cache, sp.GetRequiredService<ILogger<CachedRevocationStore>>());
        });

        return services;
    }
}
