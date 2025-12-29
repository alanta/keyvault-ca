namespace KeyVaultCa.Revocation.Ocsp.Hosting;

/// <summary>
/// Configuration options for the OCSP responder hosting package.
/// </summary>
public class OcspHostingOptions
{
    /// <summary>
    /// Configuration section name for OCSP responder options.
    /// </summary>
    public const string SectionName = "OcspResponder";

    /// <summary>
    /// Azure Key Vault URL where certificates are stored.
    /// </summary>
    public string KeyVaultUrl { get; set; } = string.Empty;

    /// <summary>
    /// Name of the OCSP signing certificate in Key Vault.
    /// Default: "ocsp-signer"
    /// </summary>
    public string OcspSignerCertName { get; set; } = "ocsp-signer";

    /// <summary>
    /// Name of the issuer (CA) certificate in Key Vault.
    /// Default: "root-ca"
    /// </summary>
    public string IssuerCertName { get; set; } = "root-ca";

    /// <summary>
    /// How many minutes OCSP responses are valid (thisUpdate to nextUpdate).
    /// Default: 10 minutes
    /// </summary>
    public int ResponseValidityMinutes { get; set; } = 10;

    /// <summary>
    /// Enable response caching for better performance.
    /// When enabled, caches OCSP responses to eliminate Table Storage lookups and Key Vault signing on cache hits.
    /// Default: false (opt-in for safety)
    /// </summary>
    public bool EnableCaching { get; set; } = false;

    /// <summary>
    /// Cache duration in minutes. Must be less than or equal to ResponseValidityMinutes.
    /// If not set or 0, defaults to ResponseValidityMinutes.
    /// Default: 0 (use ResponseValidityMinutes)
    /// </summary>
    public int CacheDurationMinutes { get; set; } = 0;
}
