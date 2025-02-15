using System.Reflection;
using McMaster.Extensions.CommandLineUtils;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace KeyVaultCa.Cli.Handlers;

public class CliApp
{
    public static IServiceProvider ServiceProvider { get; set; } = null!;
    
    public static void Configure(CommandLineApplication app)
    {
        app.Name = "keyvault-ca";
        app.Description = "A tool for managing a certificate authority in Azure Key Vault";
        app.HelpOption(inherited: true);
        app.Command("create-ca-cert", cfg => CreateCACert.Configure(cfg));
        app.Command("issue-cert", cfg => IssueCert.Configure(cfg));
        app.Command("download-cert", cfg => DownloadCert.Configure(cfg));
        app.OnExecute(() =>
        {
            app.ShowHelp();
            return 1;
        }); 
    }
    
        
    private string? GetVersion()
    {
        return typeof(CreateCACert)
            .Assembly?
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
            .InformationalVersion;
    }
}