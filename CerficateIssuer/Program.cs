using CertificateIssuer.Infrastructure;
using KeyVaultCa.Core;
using Microsoft.ApplicationInsights;
using Microsoft.ApplicationInsights.Extensibility;
using Microsoft.Extensions.Azure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

Console.WriteLine("Application starting");

var cancel = new CancellationTokenSource();

var host = new HostBuilder()
    .ConfigureDefaults(args)
    .ConfigureHostConfiguration(config =>
    {
#if DEBUG
        // Overrides for local testing must be applied after loading KeyVault data
        config.AddJsonFile("appsettings.Overrides.json", optional: true);
        config.AddUserSecrets<Program>();
#endif
    })
    .ConfigureServices((ctx, services) =>
    {
        services.AddApplicationInsightsTelemetryWorkerService(ctx.Configuration);
        services.AddSingleton<ITelemetryInitializer, FixOperationNameTelemetryInitializer>();

        services.AddScoped<KeyVaultServiceClient>();
        
        services.AddHealthChecks();
    })
    .UseConsoleLifetime()
    .Build();

var telemetryClient = host.Services.GetRequiredService<TelemetryClient>();

Console.WriteLine("Application running");
await host.RunAsync(cancel.Token);
Console.WriteLine("Stopping...");
// Explicitly call Flush() followed by sleep is required in Console Apps.
// This is to ensure that even if application terminates, telemetry is sent to the back-end.
telemetryClient.Flush();
Task.Delay(5000).Wait();

Console.WriteLine("Application stopped");