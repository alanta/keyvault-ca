using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Keys.Cryptography;
using KeyVaultCa.Core;
using KeyVaultCa.Revocation;
using KeyVaultCa.Revocation.KeyVault;
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
        long? crlNumber,
        CancellationToken cancellationToken)
    {
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

        // Get the issuer certificate from Key Vault
        var certificateClient = new CertificateClient(issuer.KeyVaultUrl, credential);
        var certResponse = await certificateClient.GetCertificateAsync(issuer.SecretName, cancellationToken);
        var issuerCertificate = X509CertificateLoader.LoadCertificate(certResponse.Value.Cer);

        _logger.LogInformation("Loaded issuer certificate: {subject}", issuerCertificate.Subject);

        // Create signature generator
        var keyUri = certResponse.Value.KeyId;
        var signatureGenerator = new KeyVaultSignatureGenerator(
            uri => new CryptographyClient(uri, credential),
            keyUri,
            issuerCertificate.SignatureAlgorithm);

        // Create Key Vault-based revocation store
        var revocationStore = new KeyVaultRevocationStore(
            uri => new CertificateClient(uri, credential),
            loggerFactory.CreateLogger<KeyVaultRevocationStore>());

        // Get revocations from the same Key Vault as the issuer
        var revocations = await revocationStore.GetRevocationsByIssuerAsync(
            issuer.KeyVaultUrl,
            issuerCertificate.Subject,
            cancellationToken);

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
        cmd.Description = "Generates a Certificate Revocation List (CRL) from revoked certificates in Key Vault.";
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

            long? crlNumber = crlNumberOption.HasValue() ? crlNumberOption.ParsedValue : null;

            var handler = new GenerateCrl(CliApp.ServiceProvider.GetRequiredService<ILoggerFactory>());
            await handler.Execute(issuer, outputPath, validityPeriod, crlNumber, cancellationToken);
        });
    }
}
