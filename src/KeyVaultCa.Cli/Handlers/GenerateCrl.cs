using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using KeyVaultCa.Core;
using KeyVaultCa.Revocation;
using KeyVaultCa.Revocation.TableStorage;
using McMaster.Extensions.CommandLineUtils;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace KeyVaultCa.Cli.Handlers;

public class GenerateCrl(ILoggerFactory loggerFactory)
{
    private readonly ILogger _logger = loggerFactory.CreateLogger<GenerateCrl>();

    public async Task Execute(
        KeyVaultSecretReference issuer,
        string outputPath,
        TimeSpan validityPeriod,
        string storageConnectionString,
        long? crlNumber,
        CancellationToken cancellationToken)
    {
        var clientFactory = new CachedClientFactory();

        // Get the issuer certificate from Key Vault
        var certificateClient = clientFactory.GetCertificateClientFactory(issuer.KeyVaultUrl);
        var certResponse = await certificateClient.GetCertificateAsync(issuer.SecretName, cancellationToken);
        var issuerCertificate = X509CertificateLoader.LoadCertificate(certResponse.Value.Cer);

        _logger.LogInformation("Loaded issuer certificate: {subject}", issuerCertificate.Subject);

        // Create signature generator
        var keyUri = certResponse.Value.KeyId;
        var signatureGenerator = new KeyVaultSignatureGenerator(
            clientFactory.GetCryptographyClient,
            keyUri,
            issuerCertificate.SignatureAlgorithm);

        // Create revocation store
        var revocationStore = new TableStorageRevocationStore(storageConnectionString, loggerFactory);

        // Generate CRL
        var crlGenerator = new CrlGenerator(revocationStore);
        _logger.LogInformation("Generating CRL for issuer: {issuer}", issuerCertificate.Subject);

        var crlBytes = await crlGenerator.GenerateCrlAsync(
            issuerCertificate,
            signatureGenerator,
            issuerCertificate.Subject,
            validityPeriod,
            HashAlgorithmName.SHA256,
            crlNumber,
            cancellationToken);

        // Write CRL to file
        await File.WriteAllBytesAsync(outputPath, crlBytes, cancellationToken);

        _logger.LogInformation("CRL generated successfully and saved to: {path}", outputPath);
        _logger.LogInformation("CRL size: {size} bytes", crlBytes.Length);
    }

    public static void Configure(CommandLineApplication cmd)
    {
        cmd.Description = "Generates a Certificate Revocation List (CRL) signed by an issuer certificate.";
        cmd.HelpOption(inherited: true);

        var kvOption = cmd.Option<string>("-kv|--key-vault <KEY_VAULT>",
            "The default Key Vault name or full URL to use when the issuer argument omits a vault reference.",
            CommandOptionType.SingleValue);

        var issuerArgument = cmd.Argument<string>("issuer",
                "Issuer certificate reference (name, secret@vault, or full URI).")
            .IsRequired();

        var outputOption = cmd.Option<string>("-o|--output <PATH>",
                "Output path for the generated CRL file.",
                CommandOptionType.SingleValue)
            .IsRequired();

        var validityOption = cmd.Option<TimeSpan>("--validity <DURATION>",
            "How long the CRL is valid (e.g., 7d, 24h, 30d). Default: 7 days.",
            CommandOptionType.SingleValue);

        var storageOption = cmd.Option<string>("--storage-connection <CONNECTION_STRING>",
                "Azure Table Storage connection string for revocation data. Can also use AZURE_STORAGE_CONNECTION_STRING environment variable.",
                CommandOptionType.SingleValue);

        var crlNumberOption = cmd.Option<long>("--crl-number <NUMBER>",
            "Sequential CRL number for tracking versions (optional but recommended).",
            CommandOptionType.SingleValue);

        cmd.OnExecuteAsync(async cancellationToken =>
        {
            var issuer = CommonOptions.ResolveSecretReference(cmd, kvOption, issuerArgument.Value!, "issuer");
            var outputPath = outputOption.Value()!;

            // Default to 7 days if not specified
            var validityPeriod = validityOption.HasValue()
                ? validityOption.ParsedValue
                : TimeSpan.FromDays(7);

            // Get storage connection string from option or environment variable
            var storageConnectionString = storageOption.Value()
                                          ?? Environment.GetEnvironmentVariable("AZURE_STORAGE_CONNECTION_STRING");

            if (string.IsNullOrEmpty(storageConnectionString))
            {
                throw new InvalidOperationException(
                    "Storage connection string must be provided via --storage-connection option or AZURE_STORAGE_CONNECTION_STRING environment variable.");
            }

            long? crlNumber = crlNumberOption.HasValue() ? crlNumberOption.ParsedValue : null;

            var handler = new GenerateCrl(CliApp.ServiceProvider.GetRequiredService<ILoggerFactory>());
            await handler.Execute(issuer, outputPath, validityPeriod, storageConnectionString, crlNumber,
                cancellationToken);
        });
    }
}
