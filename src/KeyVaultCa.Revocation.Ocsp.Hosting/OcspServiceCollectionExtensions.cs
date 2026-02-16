using System.Security.Cryptography.X509Certificates;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Keys.Cryptography;
using KeyVaultCa.Core;
using KeyVaultCa.Revocation.Interfaces;
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
    public static async Task<IServiceCollection> AddKeyVaultOcspResponder(
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
        
        var credential = new DefaultAzureCredential();
        var certClient = new CertificateClient(new Uri(options.KeyVaultUrl), credential);
        X509Certificate2 ocspSigningCert;
        X509Certificate2 issuerCert;
        Uri ocspSigningCertKeyUri;
        
        // Load OCSP signing certificate
        try
        {
            var ocspCertResponse = await certClient
                .GetCertificateAsync(options.OcspSignerCertName);
            ocspSigningCert = X509CertificateLoader
                .LoadCertificate(ocspCertResponse.Value.Cer.ToArray());
            ocspSigningCertKeyUri = ocspCertResponse.Value.KeyId;
        }
        catch (Exception exception)
        {
            throw new InvalidOperationException("Failed to load signing certificate from KeyVault", exception);
        }

        // Validate OCSP signing cert has id-kp-OCSPSigning EKU (RFC 6960 Section 4.2.2.2)
        var ekuExtension = ocspSigningCert.Extensions
            .OfType<X509EnhancedKeyUsageExtension>()
            .FirstOrDefault();

        if (ekuExtension == null || !ekuExtension.EnhancedKeyUsages
                .Cast<System.Security.Cryptography.Oid>()
                .Any(oid => oid.Value == WellKnownOids.ExtendedKeyUsages.OCSPSigning)) // id-kp-OCSPSigning
        {
            throw new InvalidOperationException(
                $"OCSP signing certificate '{options.OcspSignerCertName}' must have " +
                "Extended Key Usage extension with id-kp-OCSPSigning (1.3.6.1.5.5.7.3.9)");
        }

        try
        {
            // Load issuer certificate (root CA)
            var issuerCertResponse = await certClient
                .GetCertificateAsync(options.IssuerCertName);
            issuerCert = X509CertificateLoader
                .LoadCertificate(issuerCertResponse.Value.Cer);
        }
        catch (Exception exception)
        {
            throw new InvalidOperationException("Failed to load issuer certificate from KeyVault", exception);
        }
        
        // Register OCSP response builder as singleton for performance
        // This loads certificates from Key Vault at startup (fail-fast if unreachable)
        services.AddSingleton(sp =>
        {
            var logger = sp.GetRequiredService<ILogger<OcspResponseBuilder>>();

            // Create signature generator for OCSP signing
            var ocspCryptoClient = new CryptographyClient(ocspSigningCertKeyUri, credential);
            var signatureGenerator = new KeyVaultSignatureGenerator(
                _ => ocspCryptoClient,
                ocspSigningCertKeyUri,
                ocspSigningCert.SignatureAlgorithm);

            // Create OCSP response builder
            var revocationStore = sp.GetRequiredService<IRevocationStore>();
            var responseBuilder = new OcspResponseBuilder(
                revocationStore,
                signatureGenerator,
                ocspSigningCert,
                issuerCert,
                logger,
                TimeSpan.FromMinutes(options.ResponseValidityMinutes));

            return responseBuilder;
        });

        // Add health check for fail-fast behavior
        var healthCheck = new OcspHealthCheck();
        services.AddHealthChecks()
            .AddCheck("ocsp_ready", healthCheck);

        // Mark health check as initialized
        healthCheck.MarkInitialized();

        return services;
    }
}
