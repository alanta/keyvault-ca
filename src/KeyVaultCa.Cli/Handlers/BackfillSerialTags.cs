using System.Security.Cryptography.X509Certificates;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using KeyVaultCa.Core;
using McMaster.Extensions.CommandLineUtils;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace KeyVaultCa.Cli.Handlers;

public class BackfillSerialTags(ILoggerFactory loggerFactory)
{
    private readonly ILogger _logger = loggerFactory.CreateLogger<BackfillSerialTags>();

    public async Task Execute(string keyVault, bool dryRun, CancellationToken cancellationToken)
    {
        var credential = new DefaultAzureCredential(new DefaultAzureCredentialOptions
        {
            ExcludeEnvironmentCredential = false,
            ExcludeManagedIdentityCredential = false,
            ExcludeVisualStudioCredential = false,
            ExcludeVisualStudioCodeCredential = false,
            ExcludeAzureCliCredential = false,
            ExcludeAzurePowerShellCredential = false,
            ExcludeInteractiveBrowserCredential = true
        });
        
        var certificateClient = new CertificateClient(GetKeyVaultUri(keyVault), credential);

        _logger.LogInformation("Scanning certificates in Key Vault: {vault}", keyVault);
        
        int total = 0;
        int alreadyTagged = 0;
        int updated = 0;
        int errors = 0;

        await foreach (var certProperties in certificateClient.GetPropertiesOfCertificatesAsync(includePending: false, cancellationToken))
        {
            if (certProperties.Enabled == false) 
            {
                _logger.LogDebug("Skipping disabled certificate: {name}", certProperties.Name);
                continue;
            }

            total++;
            
            try
            {
                // Check if already has SerialNumber tag
                if (certProperties.Tags.ContainsKey("SerialNumber"))
                {
                    _logger.LogDebug("Certificate {name} already has SerialNumber tag: {serial}", 
                        certProperties.Name, certProperties.Tags["SerialNumber"]);
                    alreadyTagged++;
                    continue;
                }

                // Get the certificate to extract serial number
                var cert = await certificateClient.GetCertificateAsync(certProperties.Name, cancellationToken);
                var x509 = X509CertificateLoader.LoadCertificate(cert.Value.Cer);
                var serialNumber = x509.SerialNumber;

                if (dryRun)
                {
                    _logger.LogInformation("[DRY RUN] Would add SerialNumber tag {serial} to certificate {name}", 
                        serialNumber, certProperties.Name);
                }
                else
                {
                    // Add the tag
                    certProperties.Tags["SerialNumber"] = serialNumber;
                    await certificateClient.UpdateCertificatePropertiesAsync(certProperties, cancellationToken);
                    _logger.LogInformation("✅ Added SerialNumber tag {serial} to certificate {name}", 
                        serialNumber, certProperties.Name);
                }
                
                updated++;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ Failed to process certificate: {name}", certProperties.Name);
                errors++;
            }
        }

        Console.WriteLine();
        Console.WriteLine("=== Summary ===");
        Console.WriteLine($"Total certificates scanned: {total}");
        Console.WriteLine($"Already tagged: {alreadyTagged}");
        Console.WriteLine($"{(dryRun ? "Would update" : "Updated")}: {updated}");
        if (errors > 0)
        {
            Console.WriteLine($"Errors: {errors}");
        }
    }

    private static Uri GetKeyVaultUri(string keyVault)
    {
        var fullUrl = keyVault.StartsWith("https://", StringComparison.OrdinalIgnoreCase) 
            ? keyVault 
            : $"https://{keyVault}.vault.azure.net/";
        return new Uri(fullUrl);
    }

    public static void Configure(CommandLineApplication cmd)
    {
        cmd.Description = "Backfill SerialNumber tags on existing certificates for revocation lookups";
        cmd.HelpOption(inherited: true);
        
        var kvOption = cmd.Option("-kv|--key-vault <KEY_VAULT>", 
            "The name or full URL of the Key Vault", 
            CommandOptionType.SingleValue).IsRequired();
        var dryRunOption = cmd.Option("--dry-run", 
            "Show what would be done without making changes", 
            CommandOptionType.NoValue);
        
        cmd.OnExecuteAsync(async cancellationToken =>
        {
            var handler = new BackfillSerialTags(CliApp.ServiceProvider.GetRequiredService<ILoggerFactory>());
            await handler.Execute(kvOption.Value()!, dryRunOption.HasValue(), cancellationToken);
        });
    }
}
