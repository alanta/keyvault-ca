using Azure.Data.Tables;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using KeyVaultCa.Core;
using KeyVaultCa.Revocation;
using KeyVaultCa.Revocation.TableStorage;
using ServiceDefaults;
using System.Security.Cryptography.X509Certificates;

var builder = WebApplication.CreateBuilder(args);

builder.AddServiceDefaults();

// Configure Azure Table Storage connection
var tableConnectionString = builder.Configuration.GetConnectionString("tables")
    ?? throw new InvalidOperationException("Table Storage connection string not configured");

builder.Services.AddSingleton<TableServiceClient>(sp => new TableServiceClient(tableConnectionString));
builder.Services.AddSingleton<IRevocationStore, TableStorageRevocationStore>();

// Configure Key Vault and OCSP signing certificate
var keyVaultUrl = builder.Configuration["KeyVault:Url"]
    ?? throw new InvalidOperationException("KeyVault URL not configured. Set KeyVault:Url in configuration.");

var ocspSignerCertName = builder.Configuration["KeyVault:OcspSignerCertName"] ?? "ocsp-signer";

builder.Services.AddSingleton(sp =>
{
    var credential = new DefaultAzureCredential();
    var certClient = new CertificateClient(new Uri(keyVaultUrl), credential);

    // Download OCSP signing certificate from Key Vault
    var certResponse = certClient.DownloadCertificate(ocspSignerCertName);
    var ocspSigningCert = certResponse.Value;

    sp.GetRequiredService<ILogger<Program>>()
        .LogInformation("Loaded OCSP signing certificate: {Subject}", ocspSigningCert.Subject);

    return ocspSigningCert;
});

builder.Services.AddSingleton(sp =>
{
    var credential = new DefaultAzureCredential();
    var certClient = new CertificateClient(new Uri(keyVaultUrl), credential);
    var ocspSigningCert = sp.GetRequiredService<X509Certificate2>();

    return new KeyVaultSignatureGenerator(
        new Uri(keyVaultUrl),
        ocspSigningCert.Thumbprint,
        credential);
});

builder.Services.AddSingleton<OcspResponseBuilder>();

var app = builder.Build();

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

        logger.LogInformation("OCSP request received, size: {Size} bytes", requestBytes.Length);

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
app.MapGet("/{base64Request}", async (string base64Request, OcspResponseBuilder responseBuilder, ILogger<Program> logger) =>
{
    try
    {
        var requestBytes = Convert.FromBase64String(base64Request.Replace('_', '/').Replace('-', '+'));

        logger.LogInformation("OCSP GET request received, size: {Size} bytes", requestBytes.Length);

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

app.Run();
