using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace KeyVaultCa.Revocation.Ocsp.Hosting;

/// <summary>
/// Health check for OCSP responder readiness.
/// Ensures that certificates have been loaded from Key Vault before marking the service as healthy.
/// </summary>
public class OcspHealthCheck : IHealthCheck
{
    private bool _initialized;

    /// <summary>
    /// Marks the OCSP responder as initialized.
    /// Called by OcspServiceCollectionExtensions after successful certificate loading.
    /// </summary>
    internal void MarkInitialized() => _initialized = true;

    /// <summary>
    /// Checks if the OCSP responder is ready to handle requests.
    /// </summary>
    /// <param name="context">Health check context.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Healthy if initialized, unhealthy otherwise.</returns>
    public Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        return Task.FromResult(_initialized
            ? HealthCheckResult.Healthy("OCSP responder ready")
            : HealthCheckResult.Unhealthy("OCSP responder not initialized"));
    }
}
