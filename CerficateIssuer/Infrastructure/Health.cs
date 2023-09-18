using Microsoft.Extensions.Hosting;

namespace CertificateIssuer.Infrastructure;

public static class Health
{
    /// <summary>
    /// Signal to AKS that the application is ready
    /// </summary>
    public static void Ready()
    {
        File.WriteAllText(Path.Combine(Path.GetTempPath(), "ready"), "Ready");
    }

    /// <summary>
    /// Signal to AKS that the application is healthy
    /// </summary>
    public static async Task Update(CancellationToken token)
    {
        var healthPath = Path.Combine(Path.GetTempPath(), "health");
        if (File.Exists(healthPath))
        {
            File.SetLastWriteTime(healthPath, DateTime.Now);
        }
        else
        {
            await File.WriteAllTextAsync(healthPath, "Healthy", token);
        }
    }
}

public class HealthService : BackgroundService
{
    public override Task StartAsync(CancellationToken cancellationToken)
    {
        Health.Ready();
        return base.StartAsync(cancellationToken);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            await Health.Update(stoppingToken);
            await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);
        }
    }
}