using System.Security.Cryptography.X509Certificates;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Keys.Cryptography;
using KeyVaultCa.Core;
using KeyVaultCa.Revocation;
using KeyVaultCa.Revocation.Interfaces;
using Microsoft.AspNetCore.Http;
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

        // Configure OCSP-specific caching policy if enabled
        // Note: Consumers must add their own output caching implementation
        // (e.g., services.AddOutputCache() or services.AddStackExchangeRedisOutputCache())
        if (options.EnableCaching)
        {
            // Default cache duration to response validity if not set
            var cacheDuration = options.CacheDurationMinutes > 0
                ? options.CacheDurationMinutes
                : options.ResponseValidityMinutes;

            // Validate cache duration doesn't exceed response validity
            if (cacheDuration > options.ResponseValidityMinutes)
            {
                throw new InvalidOperationException(
                    $"CacheDurationMinutes ({cacheDuration}) cannot exceed ResponseValidityMinutes ({options.ResponseValidityMinutes}). " +
                    "Caching responses beyond their validity period would violate OCSP protocol.");
            }

            services.Configure<Microsoft.AspNetCore.OutputCaching.OutputCacheOptions>(cacheOptions =>
            {
                cacheOptions.AddPolicy("ocsp", builder =>
                {
                    builder
                        .Expire(TimeSpan.FromMinutes(cacheDuration))
                        .VaryByValue(context =>
                        {
                            // Cache key based on request body hash (contains serial number)
                            // We need to read the body, hash it, and reset the position
                            context.Request.EnableBuffering();

                            using var reader = new StreamReader(
                                context.Request.Body,
                                encoding: System.Text.Encoding.UTF8,
                                detectEncodingFromByteOrderMarks: false,
                                leaveOpen: true);

                            var body = reader.ReadToEndAsync().GetAwaiter().GetResult();
                            context.Request.Body.Position = 0; // Reset for handler

                            // Use SHA256 hash of request as cache key
                            var bodyBytes = System.Text.Encoding.UTF8.GetBytes(body);
                            var hash = System.Security.Cryptography.SHA256.HashData(bodyBytes);

                            return new KeyValuePair<string, string>(
                                "ocsp-request-hash",
                                Convert.ToBase64String(hash));
                        });
                });
            });
        }

        return services;
    }
}
