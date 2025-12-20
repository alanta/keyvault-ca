using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ServiceDefaults;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

var builder = Host.CreateApplicationBuilder(args);

builder.AddServiceDefaults();

// Configure HttpClient with client certificate and OCSP checking
builder.Services.AddHttpClient("api-server", client =>
{
    // Service discovery will resolve this to the actual API server URL
    client.BaseAddress = new Uri("https://api-server");
})
.ConfigurePrimaryHttpMessageHandler(() =>
{
    // Load client certificate
    var clientCertPath = builder.Configuration["Certificates:Client"];
    var clientCertPassword = builder.Configuration["Certificates:ClientPassword"] ?? string.Empty;

    if (string.IsNullOrEmpty(clientCertPath) || !File.Exists(clientCertPath))
    {
        throw new InvalidOperationException($"Client certificate not found at: {clientCertPath}");
    }

    var clientCert = new X509Certificate2(clientCertPath, clientCertPassword);

    var handler = new HttpClientHandler
    {
        ClientCertificates = { clientCert },
        CheckCertificateRevocationList = true, // Enable OCSP/CRL checking
        ServerCertificateCustomValidationCallback = (message, cert, chain, errors) =>
        {
            if (cert == null || chain == null)
            {
                return false;
            }

            // Load Root CA for server certificate validation
            var rootCaCertPath = builder.Configuration["Certificates:RootCA"];
            if (!string.IsNullOrEmpty(rootCaCertPath) && File.Exists(rootCaCertPath))
            {
                var rootCa = X509Certificate2.CreateFromPemFile(rootCaCertPath);
                chain.ChainPolicy.ExtraStore.Add(rootCa);
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.CustomTrustStore.Add(rootCa);
            }

            // Enable OCSP checking
            chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
            chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(30);

            bool isValid = chain.Build(cert);

            if (!isValid)
            {
                Console.WriteLine("Server certificate validation failed:");
                foreach (var status in chain.ChainStatus)
                {
                    Console.WriteLine($"  {status.Status}: {status.StatusInformation}");
                }
            }

            return isValid;
        }
    };

    return handler;
});

var app = builder.Build();

// Run the client
var httpClientFactory = app.Services.GetRequiredService<IHttpClientFactory>();
var logger = app.Services.GetRequiredService<ILogger<Program>>();

try
{
    logger.LogInformation("Starting mTLS client test...");

    var client = httpClientFactory.CreateClient("api-server");

    logger.LogInformation("Calling API server at {BaseAddress}", client.BaseAddress);

    var response = await client.GetAsync("/weatherforecast");

    if (response.IsSuccessStatusCode)
    {
        var content = await response.Content.ReadAsStringAsync();
        var weatherData = JsonSerializer.Deserialize<WeatherForecast[]>(content, new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        });

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
    }
    else
    {
        logger.LogError("❌ API call failed with status code: {StatusCode}", response.StatusCode);
        var errorContent = await response.Content.ReadAsStringAsync();
        logger.LogError("Error details: {Error}", errorContent);
    }
}
catch (HttpRequestException ex)
{
    logger.LogError(ex, "❌ HTTP request failed. This may indicate certificate validation failure.");
}
catch (Exception ex)
{
    logger.LogError(ex, "❌ Unexpected error occurred");
}

logger.LogInformation("Client test completed");

record WeatherForecast(DateOnly Date, int TemperatureC, int TemperatureF, string? Summary);
