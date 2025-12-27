using Microsoft.Extensions.Diagnostics.HealthChecks;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Keys.Cryptography;
using KeyVaultCa.Core;
using KeyVaultCa.Revocation;
using KeyVaultCa.Revocation.Interfaces;
using KeyVaultCa.Revocation.TableStorage;
using System.Security.Cryptography.X509Certificates;

var builder = WebApplication.CreateBuilder(args);

builder.AddServiceDefaults();

var credential = new DefaultAzureCredential();

// Configure Azure Table Storage connection
var tableConnectionString = builder.Configuration.GetConnectionString("tables")
    ?? throw new InvalidOperationException("Table Storage connection string not configured");

// Configure Key Vault
var keyVaultUrl = builder.Configuration["KeyVault:Url"]
    ?? throw new InvalidOperationException("KeyVault URL not configured. Set KeyVault:Url in configuration.");

var ocspSignerCertName = builder.Configuration["KeyVault:OcspSignerCertName"] ?? "ocsp-signer";
var issuerCertName = builder.Configuration["KeyVault:IssuerCertName"] ?? "root-ca";
var responseValidityMinutes = builder.Configuration.GetValue<int>("Ocsp:ResponseValidityMinutes", 10);

// Track initialization readiness for health checks
builder.Services.AddHealthChecks().AddCheck("Initialized", () =>  AppState.Initialized ? HealthCheckResult.Healthy() : HealthCheckResult.Unhealthy() );

// Register revocation store
builder.Services.AddSingleton<IRevocationStore>(sp =>
    new TableStorageRevocationStore(tableConnectionString, sp.GetRequiredService<ILoggerFactory>()));

// Register OCSP response builder with all dependencies
builder.Services.AddSingleton(sp =>
{
    var logger = sp.GetRequiredService<ILogger<OcspResponseBuilder>>();
    var certClient = new CertificateClient(new Uri(keyVaultUrl), credential);

    // Load OCSP signing certificate
    var ocspCertResponse = certClient.GetCertificateAsync(ocspSignerCertName).GetAwaiter().GetResult();
    var ocspSigningCert = X509CertificateLoader.LoadCertificate(ocspCertResponse.Value.Cer);

    logger.LogInformation("Loaded OCSP signing certificate: {subject}", ocspSigningCert.Subject);

    // Create signature generator for OCSP signing
    var ocspKeyUri = ocspCertResponse.Value.KeyId;
    var ocspCryptoClient = new CryptographyClient(ocspKeyUri, credential);
    var ocspSignatureGenerator = new KeyVaultSignatureGenerator(
        _ => ocspCryptoClient,
        ocspKeyUri,
        ocspSigningCert.SignatureAlgorithm);

    // Load issuer certificate (root CA)
    var issuerCertResponse = certClient.GetCertificateAsync(issuerCertName).GetAwaiter().GetResult();
    var issuerCert = X509CertificateLoader.LoadCertificate(issuerCertResponse.Value.Cer);

    logger.LogInformation("Loaded issuer certificate: {subject}", issuerCert.Subject);

    // Create OCSP response builder
    var revocationStore = sp.GetRequiredService<IRevocationStore>();
    return new OcspResponseBuilder(
        revocationStore,
        ocspSignatureGenerator,
        ocspSigningCert,
        issuerCert,
        logger,
        TimeSpan.FromMinutes(responseValidityMinutes));
});

var app = builder.Build();

// Warm up Key Vault access and cache signing tokens at startup; fail fast if unreachable
using (var scope = app.Services.CreateScope())
{
    _ = scope.ServiceProvider.GetRequiredService<OcspResponseBuilder>();
    AppState.Initialized = true;
}

// Minimal API endpoint for OCSP requests
app.MapPost("/", async (HttpContext context, OcspResponseBuilder responseBuilder, ILogger<Program> logger) =>
{
    try
    {
        using var ms = new MemoryStream();
        await context.Request.Body.CopyToAsync(ms);
        var requestBytes = ms.ToArray();

        if (requestBytes.Length == 0)
        {
            logger.LogWarning("Empty OCSP request received");
            return Results.BadRequest("Empty OCSP request");
        }

        logger.LogInformation("OCSP request received from {RemoteIpAddress}, size: {Size} bytes", context.Connection.RemoteIpAddress, requestBytes.Length);

        var responseBytes = await responseBuilder.BuildResponseAsync(requestBytes, context.RequestAborted);

        logger.LogInformation("OCSP response generated, size: {Size} bytes", responseBytes.Length);

        return Results.Bytes(responseBytes, "application/ocsp-response");
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "Error processing OCSP request");
        return Results.Problem("Internal server error processing OCSP request");
    }
});

// Optional: GET endpoint for base64-encoded OCSP requests (RFC 6960 Appendix A.1)
app.MapGet("/{base64Request}", async (HttpContext context, string base64Request, OcspResponseBuilder responseBuilder, ILogger<Program> logger) =>
{
    try
    {
        var requestBytes = Convert.FromBase64String(base64Request.Replace('_', '/').Replace('-', '+'));

        logger.LogInformation("OCSP GET request received from {RemoteIpAddress}, size: {Size} bytes", context.Connection.RemoteIpAddress, requestBytes.Length);

        var responseBytes = await responseBuilder.BuildResponseAsync(requestBytes, CancellationToken.None);

        logger.LogInformation("OCSP response generated, size: {Size} bytes", responseBytes.Length);

        return Results.Bytes(responseBytes, "application/ocsp-response");
    }
    catch (FormatException)
    {
        logger.LogWarning("Invalid base64 OCSP request");
        return Results.BadRequest("Invalid base64 encoding");
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "Error processing OCSP GET request");
        return Results.Problem("Internal server error processing OCSP request");
    }
});

app.MapDefaultEndpoints();

await app.RunAsync();


public static class AppState
{
    public static bool Initialized { get; set; } = false;
}