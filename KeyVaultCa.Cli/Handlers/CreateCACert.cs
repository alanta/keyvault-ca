using System.Globalization;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Keys.Cryptography;
using KeyVaultCa.Core;
using McMaster.Extensions.CommandLineUtils;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using KeyVaultCa.Cli.Validatiors;

namespace KeyVaultCa.Cli.Handlers;

public class CreateCACert(ILoggerFactory loggerFactory)
{ 
    public async Task Execute(string keyVault, string name, string? subject, DateTimeOffset notBefore, DateTimeOffset notAfter, CancellationToken cancellationToken)
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
        var kvServiceClient = new KeyVaultServiceOrchestrator(certificateClient, uri => new CryptographyClient(uri, credential), loggerFactory.CreateLogger<KeyVaultServiceOrchestrator>());
        var kvCertProvider = new KeyVaultCertificateProvider(kvServiceClient, loggerFactory.CreateLogger<KeyVaultCertificateProvider>());

        await kvCertProvider.CreateCACertificateAsync(name, subject ?? $"CN={name}", notBefore, notAfter, 1, cancellationToken);
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
        var notBeforeOption = cmd.AddNotBeforeOption();
        var notAfterOption = cmd.AddNotAfterOption();
        var durationOption = cmd.AddDurationOption();
        
        cmd.OnExecuteAsync(async cancellationToken =>
        {
            var (notBefore, notAfter) = CommonOptions.DetermineValidityPeriod(
                notBeforeOption,
                notAfterOption,
                durationOption,
                TimeSpan.FromDays(365));
            
            var handler = new CreateCACert(CliApp.ServiceProvider.GetRequiredService<ILoggerFactory>());
            await handler.Execute(kvOption.Value()!, nameArgument.Value!, commonNameOption.Value(), notBefore, notAfter, cancellationToken);
        });
    }
}