using Azure.Security.KeyVault.Certificates;
using KeyVaultCa.Core;
using McMaster.Extensions.CommandLineUtils;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace KeyVaultCa.Cli.Handlers;

public class IssueCert(ILoggerFactory loggerFactory)
{
    public async Task Execute(KeyVaultSecretReference issuer, KeyVaultSecretReference cert, DateTimeOffset notBefore, DateTimeOffset notAfter, SubjectAlternativeNames san, CancellationToken cancellationToken)
    {
        var clientFactory = new CachedClientFactory();
        
        var kvServiceClient = new KeyVaultServiceOrchestrator(clientFactory.GetCertificateClientFactory, clientFactory.GetCryptographyClient, loggerFactory.CreateLogger<KeyVaultServiceOrchestrator>());
        var kvCertProvider = new KeyVaultCertificateProvider(kvServiceClient, loggerFactory.CreateLogger<KeyVaultCertificateProvider>());

        await kvCertProvider.IssueCertificate(issuer, cert, $"CN={cert.SecretName}", notBefore, notAfter, san, cancellationToken);
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

        var dnsOption = cmd.AddDnsOption();
        var emailOption = cmd.AddEmailOption();
        var upnOption = cmd.AddUpnOption();
        
        cmd.OnExecuteAsync(async cancellationToken =>
        {
            var issuer = KeyVaultSecretReference.FromNames(kvOption.Value()!, issuerArgument.Value!);
            var cert = KeyVaultSecretReference.FromNames(kvOption.Value()!, nameArgument.Value!);
            
            var san = CommonOptions.ParseSubjectAlternativeNames(dnsOption, emailOption, upnOption);
            
            var (notBefore, notAfter) = CommonOptions.DetermineValidityPeriod(
                notBeforeOption,
                notAfterOption,
                durationOption,
                TimeSpan.FromDays(365));
            
            var handler = new IssueCert(CliApp.ServiceProvider.GetRequiredService<ILoggerFactory>());
            await handler.Execute(issuer, cert, notBefore, notAfter, san, cancellationToken);
        });
    }
}