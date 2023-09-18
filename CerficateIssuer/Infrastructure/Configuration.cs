using Microsoft.Extensions.DependencyInjection;

namespace CertificateIssuer.Infrastructure
{
    public static class Configuration
    {
        public static void AddHealthChecks(this IServiceCollection services)
        {
            services.AddHostedService<HealthService>();
        }
    }
}
