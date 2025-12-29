using System.Security.Cryptography.X509Certificates;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Keys.Cryptography;
using KeyVaultCa.Core;
using KeyVaultCa.Revocation;
using KeyVaultCa.Revocation.Interfaces;
using KeyVaultCa.Revocation.TableStorage;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace KeyVaultCa.Revocation.Ocsp.Hosting;

/// <summary>
/// Extension methods for registering OCSP responder services in the DI container.
/// </summary>
public static class OcspServiceCollectionExtensions
{
    /// <summary>
    /// Adds OCSP responder services with Azure Key Vault backend.
    /// Loads certificates from Key Vault at startup and configures the OCSP response builder.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configuration">Application configuration containing OcspResponder section.</param>
    /// <returns>The service collection for chaining.</returns>
    /// <exception cref="InvalidOperationException">Thrown if Key Vault URL is not configured.</exception>
    public static IServiceCollection AddKeyVaultOcspResponder(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        // Bind configuration
        var options = configuration.GetSection(OcspHostingOptions.SectionName)
            .Get<OcspHostingOptions>() ?? new OcspHostingOptions();

        if (string.IsNullOrWhiteSpace(options.KeyVaultUrl))
        {
            throw new InvalidOperationException(
                $"KeyVault URL not configured. Set {OcspHostingOptions.SectionName}:KeyVaultUrl in configuration.");
        }

        // Register configuration as singleton
        services.AddSingleton(options);

        // Register OCSP response builder as singleton for performance
        // This loads certificates from Key Vault at startup (fail-fast if unreachable)
        services.AddSingleton(sp =>
        {
            var logger = sp.GetRequiredService<ILogger<OcspResponseBuilder>>();
            var credential = new DefaultAzureCredential();
            var certClient = new CertificateClient(new Uri(options.KeyVaultUrl), credential);

            logger.LogInformation(
                "Loading OCSP certificates from Key Vault: {KeyVaultUrl}",
                options.KeyVaultUrl);

            // Load OCSP signing certificate
            var ocspCertResponse = certClient
                .GetCertificateAsync(options.OcspSignerCertName)
                .GetAwaiter().GetResult();
            var ocspSigningCert = X509CertificateLoader
                .LoadCertificate(ocspCertResponse.Value.Cer.ToArray());

            logger.LogInformation(
                "Loaded OCSP signing certificate: {Subject}",
                ocspSigningCert.Subject);

            // Create signature generator for OCSP signing
            var ocspKeyUri = ocspCertResponse.Value.KeyId;
            var ocspCryptoClient = new CryptographyClient(ocspKeyUri, credential);
            var signatureGenerator = new KeyVaultSignatureGenerator(
                _ => ocspCryptoClient,
                ocspKeyUri,
                ocspSigningCert.SignatureAlgorithm);

            // Load issuer certificate (root CA)
            var issuerCertResponse = certClient
                .GetCertificateAsync(options.IssuerCertName)
                .GetAwaiter().GetResult();
            var issuerCert = X509CertificateLoader
                .LoadCertificate(issuerCertResponse.Value.Cer.ToArray());

            logger.LogInformation(
                "Loaded issuer certificate: {Subject}",
                issuerCert.Subject);

            // Create OCSP response builder
            var revocationStore = sp.GetRequiredService<IRevocationStore>();
            var responseBuilder = new OcspResponseBuilder(
                revocationStore,
                signatureGenerator,
                ocspSigningCert,
                issuerCert,
                logger,
                TimeSpan.FromMinutes(options.ResponseValidityMinutes));

            // Mark health check as initialized
            OcspHealthCheck.MarkInitialized();

            logger.LogInformation("OCSP responder initialized successfully");

            return responseBuilder;
        });

        // Add health check for fail-fast behavior
        services.AddHealthChecks()
            .AddCheck<OcspHealthCheck>("ocsp_ready");

        return services;
    }

    /// <summary>
    /// Adds Azure Table Storage as the revocation store for OCSP responses.
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
