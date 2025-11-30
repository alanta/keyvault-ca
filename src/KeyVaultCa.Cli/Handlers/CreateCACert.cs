using KeyVaultCa.Core;
using McMaster.Extensions.CommandLineUtils;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace KeyVaultCa.Cli.Handlers;

public class CreateCACert(ILoggerFactory loggerFactory)
{ 
    public async Task Execute(KeyVaultSecretReference cert, string? subject, DateTimeOffset notBefore, DateTimeOffset notAfter, CancellationToken cancellationToken)
    {
        var clientFactory = new CachedClientFactory();
        
        var kvServiceClient = new KeyVaultServiceOrchestrator(clientFactory.GetCertificateClientFactory, clientFactory.GetCryptographyClient, loggerFactory.CreateLogger<KeyVaultServiceOrchestrator>());
        var kvCertProvider = new KeyVaultCertificateProvider(kvServiceClient, loggerFactory.CreateLogger<KeyVaultCertificateProvider>());

        await kvCertProvider.CreateRootCertificate(cert, subject ?? $"CN={cert.SecretName}", notBefore, notAfter, 1, cancellationToken);
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
            var cert = KeyVaultSecretReference.FromNames(kvOption.Value()!, nameArgument.Value!);
            
            var (notBefore, notAfter) = CommonOptions.DetermineValidityPeriod(
                notBeforeOption,
                notAfterOption,
                durationOption,
                TimeSpan.FromDays(365));
            
            var handler = new CreateCACert(CliApp.ServiceProvider.GetRequiredService<ILoggerFactory>());
            await handler.Execute(cert, commonNameOption.Value(), notBefore, notAfter, cancellationToken);
        });
    }
}