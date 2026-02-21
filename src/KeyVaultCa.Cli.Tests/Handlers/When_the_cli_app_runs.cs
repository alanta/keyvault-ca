using KeyVaultCa.Cli.Handlers;
using McMaster.Extensions.CommandLineUtils;
using Shouldly;

namespace KeyVaultCa.Cli.Tests.Handlers;

public class When_the_cli_app_runs
{
    [Fact]
    public void Should_support_the_version_option()
    {
        var app = new CommandLineApplication();
        app.Out = TextWriter.Null;
        app.Error = TextWriter.Null;
        CliApp.Configure(app);

        app.Execute("--version").ShouldBe(0);
    }
}
