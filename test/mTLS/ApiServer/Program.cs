using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using ServiceDefaults;
using System.Security.Cryptography.X509Certificates;

var builder = WebApplication.CreateBuilder(args);

builder.AddServiceDefaults();

// Configure Kestrel to require client certificates
builder.WebHost.ConfigureKestrel(serverOptions =>
{
    serverOptions.ConfigureHttpsDefaults(httpsOptions =>
    {
        httpsOptions.ClientCertificateMode = ClientCertificateMode.RequireCertificate;

        // Configure certificate validation with OCSP checking
        httpsOptions.CheckCertificateRevocation = true; // Enable OCSP/CRL checking

        // Custom certificate validation
        httpsOptions.ClientCertificateValidation = (cert, chain, errors) =>
        {
            var logger = serverOptions.ApplicationServices.GetRequiredService<ILogger<Program>>();

            logger.LogInformation("Validating client certificate: {Subject}", cert.Subject);
            logger.LogInformation("Certificate thumbprint: {Thumbprint}", cert.Thumbprint);

            // Check if certificate chain is valid
            if (chain == null)
            {
                logger.LogWarning("Certificate chain is null");
                return false;
            }

            // Build and validate chain with OCSP checking
            using var chainValidator = new X509Chain();
            chainValidator.ChainPolicy.RevocationMode = X509RevocationMode.Online; // Enable OCSP
            chainValidator.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
            chainValidator.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(30);
            chainValidator.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

            // Load Root CA certificate for validation
            var rootCaCertPath = builder.Configuration["Certificates:RootCA"];
            if (!string.IsNullOrEmpty(rootCaCertPath) && File.Exists(rootCaCertPath))
            {
                var rootCa = X509Certificate2.CreateFromPemFile(rootCaCertPath);
                chainValidator.ChainPolicy.ExtraStore.Add(rootCa);
                chainValidator.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chainValidator.ChainPolicy.CustomTrustStore.Add(rootCa);
                logger.LogInformation("Loaded Root CA for validation: {Subject}", rootCa.Subject);
            }

            bool isValid = chainValidator.Build(cert);

            if (!isValid)
            {
                logger.LogWarning("Certificate validation failed. Chain status:");
                foreach (var status in chainValidator.ChainStatus)
                {
                    logger.LogWarning("  {Status}: {StatusInfo}", status.Status, status.StatusInformation);
                }
            }
            else
            {
                logger.LogInformation("Certificate validation succeeded");
            }

            return isValid;
        };
    });
});

// Add certificate authentication
builder.Services.AddAuthentication(CertificateAuthenticationDefaults.AuthenticationScheme)
    .AddCertificate(options =>
    {
        options.AllowedCertificateTypes = CertificateTypes.All;
        options.RevocationMode = X509RevocationMode.Online; // Enable OCSP checking
    });

builder.Services.AddAuthorization();

var app = builder.Build();

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

var summaries = new[]
{
    "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
};

app.MapGet("/weatherforecast", () =>
{
    var forecast = Enumerable.Range(1, 5).Select(index =>
        new WeatherForecast
        (
            DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
            Random.Shared.Next(-20, 55),
            summaries[Random.Shared.Next(summaries.Length)]
        ))
        .ToArray();
    return forecast;
})
.RequireAuthorization(); // Require authenticated client certificate

app.MapDefaultEndpoints();

app.Run();

record WeatherForecast(DateOnly Date, int TemperatureC, string? Summary)
{
    public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
}
