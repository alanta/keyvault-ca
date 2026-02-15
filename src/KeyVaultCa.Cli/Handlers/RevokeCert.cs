using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using KeyVaultCa.Core;
using KeyVaultCa.Revocation;
using KeyVaultCa.Revocation.KeyVault;
using KeyVaultCa.Revocation.Models;
using McMaster.Extensions.CommandLineUtils;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace KeyVaultCa.Cli.Handlers;

public class RevokeCert(ILoggerFactory loggerFactory)
{
    private readonly ILogger<RevokeCert> _logger = loggerFactory.CreateLogger<RevokeCert>();

    public async Task Execute(
        string keyVault,
        string serialNumber,
        RevocationReason reason,
        string? comments,
        string issuerDistinguishedName,
        CancellationToken cancellationToken)
    {
        _logger.LogInformation("Revoking certificate with serial number {Serial}", serialNumber);

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

        var store = new KeyVaultRevocationStore(
            uri => new CertificateClient(uri, credential),
            loggerFactory.CreateLogger<KeyVaultRevocationStore>());

        var keyVaultUri = GetKeyVaultUri(keyVault);

        // Find the certificate by serial number
        var certName = await store.FindCertificateBySerialNumberAsync(keyVaultUri, serialNumber, cancellationToken);
        if (certName == null)
        {
            _logger.LogError("Certificate with serial number {Serial} not found in Key Vault {Vault}", 
                serialNumber, keyVault);
            throw new InvalidOperationException($"Certificate with serial number {serialNumber} not found");
        }

        await store.AddRevocationAsync(new RevocationRecord
        {
            SerialNumber = serialNumber.ToUpperInvariant(),
            RevocationDate = DateTimeOffset.UtcNow,
            Reason = reason,
            IssuerDistinguishedName = issuerDistinguishedName,
            Comments = comments
        }, cancellationToken);

        _logger.LogInformation("✅ Certificate {Name} (serial: {Serial}) has been revoked with reason: {Reason}",
            certName, serialNumber, reason);
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
        cmd.Description = "Revoke a certificate by serial number (updates certificate tags in Key Vault)";
        cmd.HelpOption(inherited: true);

        var kvOption = cmd.Option("-kv|--key-vault <KEY_VAULT>",
            "The name or full URL of the Key Vault containing the certificate",
            CommandOptionType.SingleValue).IsRequired();

        var serialArg = cmd.Argument<string>("serial", "Certificate serial number (hexadecimal)").IsRequired();

        var reasonOpt = cmd.Option<string>("--reason <REASON>",
            "Revocation reason: unspecified, keyCompromise, caCompromise, affiliationChanged, superseded, cessationOfOperation, certificateHold, privilegeWithdrawn, aaCompromise (default: unspecified)",
            CommandOptionType.SingleValue);

        var commentsOpt = cmd.Option<string>("--comments <TEXT>",
            "Optional comments about the revocation",
            CommandOptionType.SingleValue);

        var issuerOpt = cmd.Option<string>("--issuer <DN>",
            "Issuer Distinguished Name (e.g., CN=MyCA)",
            CommandOptionType.SingleValue).IsRequired();

        cmd.OnExecuteAsync(async cancellationToken =>
        {
            var reasonStr = reasonOpt.Value() ?? "unspecified";
            var reason = ParseRevocationReason(reasonStr);

            var handler = new RevokeCert(CliApp.ServiceProvider.GetRequiredService<ILoggerFactory>());
            await handler.Execute(
                kvOption.Value()!,
                serialArg.Value!,
                reason,
                commentsOpt.Value(),
                issuerOpt.Value()!,
                cancellationToken);
        });
    }

    private static RevocationReason ParseRevocationReason(string reason)
    {
        return reason.ToLowerInvariant() switch
        {
            "unspecified" => RevocationReason.Unspecified,
            "keycompromise" => RevocationReason.KeyCompromise,
            "cacompromise" => RevocationReason.CACompromise,
            "affiliationchanged" => RevocationReason.AffiliationChanged,
            "superseded" => RevocationReason.Superseded,
            "cessationofoperation" => RevocationReason.CessationOfOperation,
            "certificatehold" => RevocationReason.CertificateHold,
            "privilegewithdrawn" => RevocationReason.PrivilegeWithdrawn,
            "aacompromise" => RevocationReason.AACompromise,
            _ => throw new ArgumentException($"Unknown revocation reason: {reason}")
        };
    }
}
