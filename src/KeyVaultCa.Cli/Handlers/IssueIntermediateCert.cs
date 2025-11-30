using Azure.Security.KeyVault.Certificates;
using KeyVaultCa.Core;
using McMaster.Extensions.CommandLineUtils;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace KeyVaultCa.Cli.Handlers;

public class IssueIntermediateCert(ILoggerFactory loggerFactory)
{
    public async Task Execute(KeyVaultSecretReference issuer, KeyVaultSecretReference cert, DateTimeOffset notBefore, DateTimeOffset notAfter, SubjectAlternativeNames san, CancellationToken cancellationToken)
    {
        var clientFactory = new CachedClientFactory();
        
        var kvServiceClient = new KeyVaultServiceOrchestrator(clientFactory.GetCertificateClientFactory, clientFactory.GetCryptographyClient, loggerFactory.CreateLogger<KeyVaultServiceOrchestrator>());
        var kvCertProvider = new KeyVaultCertificateProvider(kvServiceClient, loggerFactory.CreateLogger<KeyVaultCertificateProvider>());

        await kvCertProvider.IssueIntermediateCertificate(issuer, cert, $"CN={cert.SecretName}", notBefore, notAfter, san, 0, cancellationToken);
    }
    public static void Configure(CommandLineApplication cmd)
    {
        cmd.Description = "Issues an intermediate certificate in a Key Vault.";
        cmd.HelpOption(inherited: true);
        
        var kvOption = cmd.Option<string>("-kv|--key-vault <KEY_VAULT>", "The default Key Vault name or full URL to use when certificate arguments omit a vault reference.", CommandOptionType.SingleValue);
        var issuerArgument = cmd.Argument<string>("issuer", "Issuer reference (name, secret@vault, or full URI).").IsRequired();
        var nameArgument = cmd.Argument<string>("name", "Certificate reference (name, secret@vault, or full URI).").IsRequired();
        
        var notBeforeOption = cmd.AddNotBeforeOption();
        var notAfterOption = cmd.AddNotAfterOption();
        var durationOption = cmd.AddDurationOption();
        
        var dnsOption = cmd.AddDnsOption();
        var emailOption = cmd.AddEmailOption();
        var upnOption = cmd.AddUpnOption();
        
        cmd.OnExecuteAsync(async cancellationToken =>
        {
            var issuer = CommonOptions.ResolveSecretReference(cmd, kvOption, issuerArgument.Value!, "issuer");
            var cert = CommonOptions.ResolveSecretReference(cmd, kvOption, nameArgument.Value!, "name");
            
            var (notBefore, notAfter) = CommonOptions.DetermineValidityPeriod(
                notBeforeOption,
                notAfterOption,
                durationOption,
                TimeSpan.FromDays(365));
            
            var san = CommonOptions.ParseSubjectAlternativeNames(dnsOption, emailOption, upnOption);
            
            var handler = new IssueIntermediateCert(CliApp.ServiceProvider.GetRequiredService<ILoggerFactory>());
            await handler.Execute(issuer, cert, notBefore, notAfter, san, cancellationToken);
        });
    }
}