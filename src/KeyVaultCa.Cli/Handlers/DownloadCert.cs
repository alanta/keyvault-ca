using System.Security.Cryptography.X509Certificates;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using McMaster.Extensions.CommandLineUtils;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace KeyVaultCa.Cli.Handlers;

public class DownloadCert(ILoggerFactory loggerFactory)
{
    public async Task Execute(string keyVault, string name, bool key, CancellationToken cancellationToken)
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
        
        Console.WriteLine("Exporting certificate to {0}.pem", name);
        await File.WriteAllTextAsync($"{name}.pem", cert.Value.ExportCertificatePem(), cancellationToken);
        
        if( key )
        {
            // TODO : handle other key types
            Console.WriteLine("Exporting RSA key to {0}.key", name);
            await File.WriteAllTextAsync($"{name}.key", cert.Value.GetRSAPrivateKey()!.ExportRSAPrivateKeyPem(), cancellationToken);
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
        var nameArgument = cmd.Argument<string>("name", "The name of the certificate").IsRequired();
        
        cmd.OnExecuteAsync(async cancellationToken =>
        {
            var handler = new DownloadCert(CliApp.ServiceProvider.GetRequiredService<ILoggerFactory>());
            await handler.Execute(kvOption.Value()!, nameArgument.Value!, keyOption.HasValue(), cancellationToken);
        });
    }
}