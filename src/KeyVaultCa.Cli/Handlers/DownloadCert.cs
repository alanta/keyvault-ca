using System.Security.Cryptography.X509Certificates;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using KeyVaultCa.Cli.Validators;
using McMaster.Extensions.CommandLineUtils;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace KeyVaultCa.Cli.Handlers;

public class DownloadCert
{
    public async Task<int> Execute(string keyVault, string name, bool key, bool pfx, string? pfxPassword, bool noPassword, CancellationToken cancellationToken)
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

        // First, get the certificate to check if it's a CA certificate
        var certInfo = await certificateClient.GetCertificateAsync(name, cancellationToken);
        var publicCert = X509CertificateLoader.LoadCertificate(certInfo.Value.Cer);
        
        // Check if this is a CA certificate
        var isCaCert = IsCaCertificate(publicCert);
        
        // Block private key export for CA certificates
        if (isCaCert && key)
        {
            Console.Error.WriteLine("Error: Cannot export private key for CA certificates. The private key must remain in Key Vault.");
            Console.Error.WriteLine("To download only the public certificate, omit the --key flag.");
            return 1;
        }
        
        // Download with private key only if needed and allowed
        X509Certificate2 cert;
        if (key) 
        {
            cert = await certificateClient.DownloadCertificateAsync(name, null, cancellationToken);
        }
        else
        {
            cert = publicCert;
        }
        
        if( pfx )
        {
            // Only prompt for password if private key is included
            string? password = null;
            if (key)
            {
                password = pfxPassword;
                if (string.IsNullOrEmpty(password) && !noPassword)
                {
                    password = Prompt.GetPassword("Enter password for PFX file (leave empty for no password): ");
                }
            }
            
            var certType = key ? "certificate with private key" : "certificate";
            Console.WriteLine("Exporting {0} to {1}.pfx", certType, name);
            var pfxBytes = cert.Export(X509ContentType.Pfx, password);
            await File.WriteAllBytesAsync($"{name}.pfx", pfxBytes, cancellationToken);
            
            if (key)
            {
                if (!string.IsNullOrEmpty(password))
                {
                    Console.WriteLine("PFX file is password protected");
                }
                else
                {
                    Console.WriteLine("Warning: PFX file is not password protected");
                }
            }
        }
        else
        {
            Console.WriteLine("Exporting certificate to {0}.crt", name);
            await File.WriteAllTextAsync($"{name}.crt", cert.ExportCertificatePem(), cancellationToken);
            
            if( key )
            {
                // TODO : handle other key types
                Console.WriteLine("Exporting RSA key to {0}.key", name);
                await File.WriteAllTextAsync($"{name}.key", cert.GetRSAPrivateKey()!.ExportRSAPrivateKeyPem(), cancellationToken);
            }
        }

        return 0;
    }

    private static bool IsCaCertificate(X509Certificate2 certificate)
    {
        // Check for BasicConstraints extension with CA=true
        var basicConstraints = certificate.Extensions
            .OfType<X509BasicConstraintsExtension>()
            .FirstOrDefault();
            
        return basicConstraints?.CertificateAuthority == true;
    }
    
    private static Uri GetKeyVaultUri(string keyVault)
    {
        var fullUrl = keyVault.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ? keyVault : $"https://{keyVault}.vault.azure.net/";
        return new Uri(fullUrl);
    }

    public static void Configure(CommandLineApplication cmd)
    {
        cmd.Description = "Download a certificate from a Key Vault.";
        cmd.HelpOption(inherited: true);
        
        var kvOption = cmd.Option("-kv|--key-vault <KEY_VAULT>", "The name or full URL of the Key Vault", CommandOptionType.SingleValue).IsRequired();
        var keyOption = cmd.Option("-k|--key", "Include the private key in the export", CommandOptionType.NoValue);
        var pfxOption = cmd.Option("-p|--pfx", "Export as PFX (PKCS#12) format (use with --key to include private key)", CommandOptionType.NoValue);
        var pfxPasswordOption = cmd.Option("-pw|--pfx-password <PASSWORD>", "Password to protect the PFX file (optional)", CommandOptionType.SingleValue);
        var noPasswordOption = cmd.Option("-np|--no-password", "Skip password prompt and create unprotected PFX (for automation)", CommandOptionType.NoValue);
        var nameArgument = cmd.Argument<string>("name", "The name of the certificate").IsRequired().AcceptsKeyVaultName();
        
        cmd.OnExecuteAsync(async cancellationToken =>
        {
            var handler = new DownloadCert();
            return await handler.Execute(kvOption.Value()!, nameArgument.Value!, keyOption.HasValue(), pfxOption.HasValue(), pfxPasswordOption.Value(), noPasswordOption.HasValue(), cancellationToken);
        });
    }
}