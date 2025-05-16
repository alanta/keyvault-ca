using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Keys.Cryptography;
using KeyVaultCa.Core;
using McMaster.Extensions.CommandLineUtils;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace KeyVaultCa.Cli.Handlers;

public class IssueCert(ILoggerFactory loggerFactory)
{
    public async Task Execute(string keyVault, string issuer, string name, DateTimeOffset notBefore, DateTimeOffset notAfter, CancellationToken cancellationToken)
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
        

        await kvCertProvider.IssueCertificate(issuer, name, $"CN={name}", notBefore, notAfter, cancellationToken);
    }
    
    private static Uri GetKeyVaultUri(string keyVault)
    {
        var fullUrl = keyVault.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ? keyVault : $"https://{keyVault}.vault.azure.net/";
        return new Uri(fullUrl);
    }

    public static void Configure(CommandLineApplication cmd)
    {
        cmd.Description = "Issues a certificate in a Key Vault.";
        cmd.HelpOption(inherited: true);
        
        var kvOption = cmd.Option("-kv|--key-vault <KEY_VAULT>", "The name or full URL of the Key Vault", CommandOptionType.SingleValue).IsRequired();
        var issuerArgument = cmd.Argument<string>("issuer", "The name of the issuer certificate").IsRequired();
        var nameArgument = cmd.Argument<string>("name", "The name of the certificate").IsRequired();
        
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
            
            var handler = new IssueCert(CliApp.ServiceProvider.GetRequiredService<ILoggerFactory>());
            await handler.Execute(kvOption.Value()!, issuerArgument.Value!, nameArgument.Value!, notBefore, notAfter, cancellationToken);
        });
    }
}