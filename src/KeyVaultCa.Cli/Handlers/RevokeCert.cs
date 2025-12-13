using KeyVaultCa.Revocation.Interfaces;
using KeyVaultCa.Revocation.Models;
using KeyVaultCa.Revocation.TableStorage;
using McMaster.Extensions.CommandLineUtils;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace KeyVaultCa.Cli.Handlers;

public class RevokeCert(ILoggerFactory loggerFactory)
{
    private readonly ILogger<RevokeCert> _logger = loggerFactory.CreateLogger<RevokeCert>();

    public async Task Execute(
        string serialNumber,
        RevocationReason reason,
        string? comments,
        string issuerDistinguishedName,
        string storageConnectionString,
        CancellationToken cancellationToken)
    {
        _logger.LogInformation("Revoking certificate with serial number {Serial}", serialNumber);

        var store = new TableStorageRevocationStore(storageConnectionString, loggerFactory);

        await store.AddRevocationAsync(new RevocationRecord
        {
            SerialNumber = serialNumber.ToUpperInvariant(),
            RevocationDate = DateTimeOffset.UtcNow,
            Reason = reason,
            IssuerDistinguishedName = issuerDistinguishedName,
            Comments = comments
        }, cancellationToken);

        _logger.LogInformation("Certificate {Serial} has been revoked with reason: {Reason}",
            serialNumber, reason);
    }

    public static void Configure(CommandLineApplication cmd)
    {
        cmd.Description = "Revoke a certificate by serial number";
        cmd.HelpOption(inherited: true);

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

        var storageOpt = cmd.Option<string>("--storage <CONNECTION_STRING>",
            "Azure Table Storage connection string (or environment variable name)",
            CommandOptionType.SingleValue).IsRequired();

        cmd.OnExecuteAsync(async cancellationToken =>
        {
            var reasonStr = reasonOpt.Value() ?? "unspecified";
            var reason = ParseRevocationReason(reasonStr);

            var storageConnection = GetConnectionString(storageOpt.Value()!);

            var handler = new RevokeCert(CliApp.ServiceProvider.GetRequiredService<ILoggerFactory>());
            await handler.Execute(
                serialArg.Value!,
                reason,
                commentsOpt.Value(),
                issuerOpt.Value()!,
                storageConnection,
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

    private static string GetConnectionString(string value)
    {
        // Check if it's an environment variable
        var envValue = Environment.GetEnvironmentVariable(value);
        if (!string.IsNullOrEmpty(envValue))
        {
            return envValue;
        }

        // Otherwise, treat it as a connection string
        return value;
    }
}
