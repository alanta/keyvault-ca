using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Keys.Cryptography;
using KeyVaultCa.Core;
using McMaster.Extensions.CommandLineUtils;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace KeyVaultCa.Cli.Handlers;

public class CreateCACert(ILoggerFactory _loggerFactory)
{ 
    public async Task Execute(string keyVault, string name, string? subject, CancellationToken cancellationToken)
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
        var kvServiceClient = new KeyVaultServiceClient(certificateClient, uri => new CryptographyClient(uri, credential), _loggerFactory.CreateLogger<KeyVaultServiceClient>());
        var kvCertProvider = new KeyVaultCertificateProvider(kvServiceClient, _loggerFactory.CreateLogger<KeyVaultCertificateProvider>());

        await kvCertProvider.CreateCACertificateAsync(name, subject ?? $"CN={name}", 1, cancellationToken);
    }
    
    private static Uri GetKeyVaultUri(string keyVault)
    {
        var fullUrl = keyVault.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ? keyVault : $"https://{keyVault}.vault.azure.net/";
        return new Uri(fullUrl);
    }

    public static void Configure(CommandLineApplication cmd)
    {
        cmd.Description = "Creates a CA certificate in a Key Vault.";
        cmd.HelpOption(inherited: true);
        
        var kvOption = cmd.Option("-kv|--key-vault <KEY_VAULT>", "The name or full URL of the Key Vault", CommandOptionType.SingleValue).IsRequired();
        var nameArgument = cmd.Argument<string>("name", "The name of the certificate").IsRequired();
        var commonNameOption = cmd.Option("-cn|--common-name <COMMON_NAME>", "The common name of the certificate", CommandOptionType.SingleValue);
        
        cmd.OnExecuteAsync(async cancellationToken =>
        {
            var handler = new CreateCACert(CliApp.ServiceProvider.GetRequiredService<ILoggerFactory>());
            await handler.Execute(kvOption.Value(), nameArgument.Value, commonNameOption.Value(), cancellationToken);
        });
    }
}