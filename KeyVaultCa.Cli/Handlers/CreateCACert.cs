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
    public async Task Execute(string keyVault, string name, string? subject, DateTime notBefore, DateTime notAfter, CancellationToken cancellationToken)
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
        var kvServiceClient = new KeyVaultServiceClient(certificateClient, uri => new CryptographyClient(uri, credential), loggerFactory.CreateLogger<KeyVaultServiceClient>());
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
        var notBeforeOption = cmd.Option<DateTime>("-nb|--not-before <COMMON_NAME>",
                "The date and time the certificate becomes valid. Defaults to current date and time.",
                CommandOptionType.SingleValue)
            .AcceptsUtcDate();
        var notAftereOption = cmd.Option<DateTime>("-na|--not-after <COMMON_NAME>",
                "The date and time until which the certificate is valid. Defaults to current date and time + 1 year",
                CommandOptionType.SingleValue)
            .AcceptsUtcDate();
        var durationOption = cmd.Option<TimeSpan>("-d|--duration <DURATION>",
                "The validity period of the certificate in ISO 8601 format. For example for 30 days. Default is 1 calendar year. If --not-after is specified, this is ignored.",
                CommandOptionType.SingleValue)
            .AcceptsDuration();
        
        cmd.OnExecuteAsync(async cancellationToken =>
        {
            var notBefore = notBeforeOption.HasValue()
                ? DateTime.TryParse(notBeforeOption.Value()!, CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed)
                    ? parsed
                    : DateTime.UtcNow
                : DateTime.UtcNow;

            var duration = durationOption.HasValue()
                ? TimeSpan.TryParse(durationOption.Value()!, CultureInfo.InvariantCulture, out var parsed3)
                    ? parsed3
                    : TimeSpan.FromDays(365)
                : TimeSpan.FromDays(365); 
            
            var notAfter = notAftereOption.HasValue()
                ? DateTime.TryParse(notAftereOption.Value()!, CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed2)
                    ? parsed2
                    : notBefore+duration
                : notBefore + duration;
            
            var handler = new CreateCACert(CliApp.ServiceProvider.GetRequiredService<ILoggerFactory>());
            await handler.Execute(kvOption.Value()!, nameArgument.Value!, commonNameOption.Value(), notBefore, notAfter, cancellationToken);
        });
    }
}