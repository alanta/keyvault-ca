using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

var builder = Host.CreateApplicationBuilder(args);

builder.AddServiceDefaults();

// Create ActivitySource for custom tracing - use the application name for proper correlation
var activitySource = new ActivitySource(builder.Environment.ApplicationName);

// Load validation settings
var trustedIssuer = builder.Configuration.GetValue<string>("Certificates:TrustedIssuer")
    ?? throw new InvalidOperationException("Certificates:TrustedIssuer not configured");
var expectedServerSubject = builder.Configuration.GetValue<string>("Certificates:ExpectedServerSubject")
    ?? throw new InvalidOperationException("Certificates:ExpectedServerSubject not configured");

// Configure HttpClient with client certificate and OCSP checking
builder.Services.AddHttpClient("api-server", client =>
{
    // Service discovery will resolve this to the actual API server URL
    client.BaseAddress = new Uri("https://api-server");
})
.ConfigurePrimaryHttpMessageHandler(() =>
{
    // Load client certificate
    var clientCertPath = builder.Configuration.GetValue<string>("Certificates:Client");
    var clientCertPassword = builder.Configuration.GetValue<string>("Certificates:ClientPassword") ?? string.Empty;

    if (string.IsNullOrEmpty(clientCertPath) || !File.Exists(clientCertPath))
        throw new InvalidOperationException($"Client certificate not found at: {clientCertPath}");

    var clientCert = X509CertificateLoader.LoadPkcs12FromFile(clientCertPath, clientCertPassword);

    // Enable OCSP checking with system trust
    // NOTE: This requires the root CA to be installed in the system trust store
    var handler = new HttpClientHandler
    {
        ClientCertificates = { clientCert },
        CheckCertificateRevocationList = true,
        ServerCertificateCustomValidationCallback = (message, cert, chain, sslErrors) =>
        {
            if (cert == null) return false;

            // Verify server cert was issued by our trusted CA
            if (!string.Equals(cert.Issuer, trustedIssuer, StringComparison.OrdinalIgnoreCase))
                return false;

            // Verify server cert subject matches expected
            if (!string.Equals(cert.Subject, expectedServerSubject, StringComparison.OrdinalIgnoreCase))
                return false;

            // Allow standard validation to complete (chain trust, revocation, etc.)
            return sslErrors == System.Net.Security.SslPolicyErrors.None;
        }
    };

    return handler;
});

// Add the client worker as a hosted service
builder.Services.AddHostedService<ClientWorker>();

// Register the ActivitySource as a singleton so the worker can use it
builder.Services.AddSingleton(activitySource);

var app = builder.Build();

// Run will start all hosted services and wait for shutdown
await app.RunAsync();

record WeatherForecast(DateOnly Date, int TemperatureC, int TemperatureF, string? Summary);

class ClientWorker(
    IHttpClientFactory httpClientFactory,
    ILogger<ClientWorker> logger,
    ActivitySource activitySource,
    IHostApplicationLifetime lifetime) : BackgroundService
{
    private const int NumberOfRuns = 3;
    private static readonly TimeSpan DelayBetweenRuns = TimeSpan.FromSeconds(10);
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var client = httpClientFactory.CreateClient("api-server");

        for (int run = 1; run <= NumberOfRuns; run++)
        {
            logger.LogInformation("=== Run {Run}/{Total} ===", run, NumberOfRuns);

            await MakeRequestAsync(client, run, stoppingToken);

            if (run < NumberOfRuns)
            {
                logger.LogInformation("Waiting {Delay} seconds before next run...", DelayBetweenRuns.TotalSeconds);
                await Task.Delay(DelayBetweenRuns, stoppingToken);
            }
        }

        logger.LogInformation("All runs completed. Shutting down to flush telemetry...");

        // Give telemetry a moment to flush, then stop the application
        await Task.Delay(2000, stoppingToken);
        lifetime.StopApplication();
    }

    private async Task MakeRequestAsync(HttpClient client, int runNumber, CancellationToken stoppingToken)
    {
        using var activity = activitySource.StartActivity("mTLS Weather Forecast Request", ActivityKind.Client);

        activity?.SetTag("http.url", client.BaseAddress?.ToString());
        activity?.SetTag("test.type", "mTLS with OCSP");
        activity?.SetTag("test.run", runNumber);

        try
        {
            logger.LogInformation("Calling API server at {BaseAddress}", client.BaseAddress);

            var response = await client.GetAsync("/weatherforecast", stoppingToken);

            activity?.SetTag("http.status_code", (int)response.StatusCode);

            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync(stoppingToken);
                var weatherData = JsonSerializer.Deserialize<WeatherForecast[]>(content, JsonOptions);

                logger.LogInformation("✅ Successfully received weather forecast from API:");
                Console.WriteLine();
                Console.WriteLine("Weather Forecast:");
                Console.WriteLine("==================");

                if (weatherData != null)
                {
                    foreach (var forecast in weatherData)
                    {
                        Console.WriteLine($"{forecast.Date:yyyy-MM-dd}: {forecast.TemperatureC}°C ({forecast.TemperatureF}°F) - {forecast.Summary}");
                    }
                }

                Console.WriteLine();
                logger.LogInformation("✅ mTLS communication successful with OCSP validation!");

                activity?.SetTag("test.result", "success");
                activity?.SetStatus(ActivityStatusCode.Ok, "Test completed");
            }
            else
            {
                logger.LogError("❌ API call failed with status code: {StatusCode}", response.StatusCode);
                var errorContent = await response.Content.ReadAsStringAsync(stoppingToken);
                logger.LogError("Error details: {Error}", errorContent);

                activity?.SetTag("test.result", "failed");
                activity?.SetStatus(ActivityStatusCode.Error, $"HTTP {response.StatusCode}");
            }
        }
        catch (HttpRequestException ex)
        {
            logger.LogError(ex, "❌ HTTP request failed. This may indicate certificate validation failure.");
            activity?.SetStatus(ActivityStatusCode.Error, ex.Message);
            activity?.SetTag("test.result", "error");
            activity?.SetTag("error.type", ex.GetType().Name);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "❌ Unexpected error occurred");
            activity?.SetStatus(ActivityStatusCode.Error, ex.Message);
            activity?.SetTag("test.result", "error");
            activity?.SetTag("error.type", ex.GetType().Name);
        }
    }
    
}
