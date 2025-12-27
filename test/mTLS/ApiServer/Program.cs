using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using System.Security.Cryptography.X509Certificates;

var builder = WebApplication.CreateBuilder(args);

builder.AddServiceDefaults();

// Load server certificate from configuration
var serverCertPath = builder.Configuration.GetValue<string>("Certificates:Server")
    ?? throw new InvalidOperationException("Certificates:Server not configured");
var serverCertPassword = builder.Configuration.GetValue<string>("Certificates:ServerPassword") ?? string.Empty;

if (!File.Exists(serverCertPath))
    throw new InvalidOperationException($"Server certificate not found at: {serverCertPath}");

var serverCert = X509CertificateLoader.LoadPkcs12FromFile(serverCertPath, serverCertPassword);

// Configure Kestrel for mTLS with OCSP validation
// NOTE: Requires root CA in system trust store (run: scripts/manage-trust-store.sh install)
builder.WebHost.ConfigureKestrel(serverOptions =>
{
    serverOptions.ConfigureHttpsDefaults(httpsOptions =>
    {
        httpsOptions.ServerCertificate = serverCert;
        httpsOptions.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
        httpsOptions.CheckCertificateRevocation = true;
    });
});

// Load validation settings
var trustedIssuer = builder.Configuration.GetValue<string>("Certificates:TrustedIssuer")
    ?? throw new InvalidOperationException("Certificates:TrustedIssuer not configured");
var allowedClients = builder.Configuration.GetSection("Certificates:AllowedClients").Get<string[]>()
    ?? throw new InvalidOperationException("Certificates:AllowedClients not configured");

// Certificate authentication (revocation already checked by Kestrel)
builder.Services.AddAuthentication(CertificateAuthenticationDefaults.AuthenticationScheme)
    .AddCertificate(options =>
    {
        options.AllowedCertificateTypes = CertificateTypes.Chained;
        options.RevocationMode = X509RevocationMode.NoCheck; // Already checked at TLS layer

        options.Events = new CertificateAuthenticationEvents
        {
            OnCertificateValidated = context =>
            {
                var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                var clientCert = context.ClientCertificate;

                // Verify the certificate was issued by our trusted CA
                if (!string.Equals(clientCert.Issuer, trustedIssuer, StringComparison.OrdinalIgnoreCase))
                {
                    logger.LogWarning("❌ Client certificate issued by untrusted CA: {Issuer}", clientCert.Issuer);
                    context.Fail("Certificate not issued by trusted CA");
                    return Task.CompletedTask;
                }

                // Verify client is in the allowed list
                if (!allowedClients.Contains(clientCert.Subject))
                {
                    logger.LogWarning("❌ Client not in allowed list: {Subject}", clientCert.Subject);
                    context.Fail("Client not authorized");
                    return Task.CompletedTask;
                }

                logger.LogInformation("✅ Client certificate validated: {Subject}", clientCert.Subject);
                return Task.CompletedTask;
            },
            OnAuthenticationFailed = context =>
            {
                var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                logger.LogError(context.Exception, "❌ Certificate authentication failed");
                return Task.CompletedTask;
            }
        };
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
