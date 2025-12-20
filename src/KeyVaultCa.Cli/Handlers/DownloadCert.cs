using System.Security.Cryptography.X509Certificates;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using McMaster.Extensions.CommandLineUtils;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace KeyVaultCa.Cli.Handlers;

public class DownloadCert(ILoggerFactory loggerFactory)
{
    public async Task Execute(string keyVault, string name, bool key, bool pfx, string? pfxPassword, bool noPassword, CancellationToken cancellationToken)
    {
        var credential = new DefaultAzureCredential(new DefaultAzureCredentialOptions
        {
            ExcludeWorkloadIdentityCredential = true,
            ExcludeManagedIdentityCredential = true,
            ExcludeAzureDeveloperCliCredential = true,
            ExcludeVisualStudioCodeCredential = true, 
            ExcludeVisualStudioCredential = true,
            ExcludeAzurePowerShellCredential = true,
            ExcludeInteractiveBrowserCredential = true
        });
        var certificateClient = new CertificateClient(GetKeyVaultUri(keyVault), credential);

        var cert = await certificateClient.DownloadCertificateAsync(name,null,cancellationToken);
        
        if( pfx )
        {
            // Prompt for password if not provided and not explicitly skipped
            var password = pfxPassword;
            if (string.IsNullOrEmpty(password) && !noPassword)
            {
                password = Prompt.GetPassword("Enter password for PFX file (leave empty for no password): ");
            }
            
            Console.WriteLine("Exporting certificate with private key to {0}.pfx", name);
            var pfxBytes = cert.Value.Export(X509ContentType.Pfx, password);
            await File.WriteAllBytesAsync($"{name}.pfx", pfxBytes, cancellationToken);
            
            if (!string.IsNullOrEmpty(password))
            {
                Console.WriteLine("PFX file is password protected");
            }
            else
            {
                Console.WriteLine("Warning: PFX file is not password protected");
            }
        }
        else
        {
            Console.WriteLine("Exporting certificate to {0}.pem", name);
            await File.WriteAllTextAsync($"{name}.pem", cert.Value.ExportCertificatePem(), cancellationToken);
            
            if( key )
            {
                // TODO : handle other key types
                Console.WriteLine("Exporting RSA key to {0}.key", name);
                await File.WriteAllTextAsync($"{name}.key", cert.Value.GetRSAPrivateKey()!.ExportRSAPrivateKeyPem(), cancellationToken);
            }
        }

    }
    
    private static Uri GetKeyVaultUri(string keyVault)
    {
        var fullUrl = keyVault.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ? keyVault : $"https://{keyVault}.vault.azure.net/";
        return new Uri(fullUrl);
    }

    public static void Configure(CommandLineApplication cmd)
    {
        cmd.Description = "Download a certificate from a Key Vault.";
        cmd.HelpOption(inherited: true);
        
        var kvOption = cmd.Option("-kv|--key-vault <KEY_VAULT>", "The name or full URL of the Key Vault", CommandOptionType.SingleValue).IsRequired();
        var keyOption = cmd.Option("-k|--key", "Download the key as well", CommandOptionType.NoValue);
        var pfxOption = cmd.Option("-p|--pfx", "Export as PFX (PKCS#12) format with private key", CommandOptionType.NoValue);
        var pfxPasswordOption = cmd.Option("-pw|--pfx-password <PASSWORD>", "Password to protect the PFX file (optional)", CommandOptionType.SingleValue);
        var noPasswordOption = cmd.Option("-np|--no-password", "Skip password prompt and create unprotected PFX (for automation)", CommandOptionType.NoValue);
        var nameArgument = cmd.Argument<string>("name", "The name of the certificate").IsRequired();
        
        cmd.OnExecuteAsync(async cancellationToken =>
        {
            var handler = new DownloadCert(CliApp.ServiceProvider.GetRequiredService<ILoggerFactory>());
            await handler.Execute(kvOption.Value()!, nameArgument.Value!, keyOption.HasValue(), pfxOption.HasValue(), pfxPasswordOption.Value(), noPasswordOption.HasValue(), cancellationToken);
        });
    }
}