using System.Security.Cryptography.X509Certificates;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Keys.Cryptography;
using KeyVaultCa.Core;
using KeyVaultCa.Revocation;
using KeyVaultCa.Revocation.Interfaces;
using KeyVaultCa.Revocation.TableStorage;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container
builder.Services.AddControllers();
builder.Services.AddHealthChecks();

// Configure logging
builder.Logging.AddConsole();
builder.Logging.AddDebug();

// Azure authentication
var credential = new DefaultAzureCredential();

// Configuration
var ocspSigningKeyVaultUrl = builder.Configuration["OcspSigning:KeyVaultUrl"]
    ?? throw new InvalidOperationException("OcspSigning:KeyVaultUrl configuration is required");
var ocspSigningCertName = builder.Configuration["OcspSigning:CertificateName"]
    ?? throw new InvalidOperationException("OcspSigning:CertificateName configuration is required");
var issuerKeyVaultUrl = builder.Configuration["Issuer:KeyVaultUrl"]
    ?? throw new InvalidOperationException("Issuer:KeyVaultUrl configuration is required");
var issuerCertName = builder.Configuration["Issuer:CertificateName"]
    ?? throw new InvalidOperationException("Issuer:CertificateName configuration is required");
var storageConnectionString = builder.Configuration["TableStorage:ConnectionString"]
    ?? Environment.GetEnvironmentVariable("AZURE_STORAGE_CONNECTION_STRING")
    ?? throw new InvalidOperationException("TableStorage:ConnectionString configuration or AZURE_STORAGE_CONNECTION_STRING environment variable is required");

// Register revocation store
builder.Services.AddSingleton<IRevocationStore>(sp =>
    new TableStorageRevocationStore(storageConnectionString, sp.GetRequiredService<ILoggerFactory>()));

// Load certificates and create OCSP response builder
builder.Services.AddSingleton(sp =>
{
    var logger = sp.GetRequiredService<ILogger<OcspResponseBuilder>>();

    // Load OCSP signing certificate
    var ocspCertClient = new CertificateClient(new Uri(ocspSigningKeyVaultUrl), credential);
    var ocspCertResponse = ocspCertClient.GetCertificateAsync(ocspSigningCertName).GetAwaiter().GetResult();
    var ocspSigningCert = new X509Certificate2(ocspCertResponse.Value.Cer);

    logger.LogInformation("Loaded OCSP signing certificate: {subject}", ocspSigningCert.Subject);

    // Create signature generator for OCSP signing
    var ocspKeyUri = ocspCertResponse.Value.KeyId;
    var ocspCryptoClient = new CryptographyClient(ocspKeyUri, credential);
    var ocspSignatureGenerator = new KeyVaultSignatureGenerator(
        _ => ocspCryptoClient,
        ocspKeyUri,
        ocspSigningCert.SignatureAlgorithm);

    // Load issuer certificate
    var issuerCertClient = new CertificateClient(new Uri(issuerKeyVaultUrl), credential);
    var issuerCertResponse = issuerCertClient.GetCertificateAsync(issuerCertName).GetAwaiter().GetResult();
    var issuerCert = new X509Certificate2(issuerCertResponse.Value.Cer);

    logger.LogInformation("Loaded issuer certificate: {subject}", issuerCert.Subject);

    // Create OCSP response builder
    var revocationStore = sp.GetRequiredService<IRevocationStore>();
    return new OcspResponseBuilder(
        revocationStore,
        ocspSignatureGenerator,
        ocspSigningCert,
        issuerCert,
        logger);
});

var app = builder.Build();

// Configure the HTTP request pipeline
app.MapControllers();
app.MapHealthChecks("/health");

app.Run();
