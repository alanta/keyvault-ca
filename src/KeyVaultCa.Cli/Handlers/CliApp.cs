using System.Reflection;
using KeyVaultCa.Cli.Validators;
using McMaster.Extensions.CommandLineUtils;

namespace KeyVaultCa.Cli.Handlers;

public class CliApp
{
    public static IServiceProvider ServiceProvider { get; set; } = null!;
    
    public static void Configure(CommandLineApplication app)
    {
        app.Name = "keyvaultca";
        app.Description = "A tool for managing a certificate authority in Azure Key Vault";
        app.ValueParsers.AddOrReplace(new TimeSpanValueParser());
        app.HelpOption(inherited: true);
        app.Command("create-ca-cert", CreateCACert.Configure);
        app.Command("issue-intermediate-cert", IssueIntermediateCert.Configure);
        app.Command("issue-cert", IssueCert.Configure);
        app.Command("download-cert", DownloadCert.Configure);
        app.Command("revoke-cert", RevokeCert.Configure);
        app.Command("generate-crl", GenerateCrl.Configure);
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