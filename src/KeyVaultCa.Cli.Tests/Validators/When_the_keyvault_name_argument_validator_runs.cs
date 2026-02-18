using KeyVaultCa.Cli.Validators;
using McMaster.Extensions.CommandLineUtils;
using Shouldly;

namespace KeyVaultCa.Cli.Tests.Validators;

public class When_the_keyvault_name_argument_validator_runs
{
    private static int ExecuteWithName(string? name)
    {
        var app = new CommandLineApplication();
        app.Out = TextWriter.Null;
        app.Error = TextWriter.Null;
        app.Argument<string>("name", "The certificate name").AcceptsKeyVaultName();
        app.OnExecute(() => 0);
        return name is null ? app.Execute() : app.Execute(name);
    }

    [Fact]
    public void Should_pass_for_a_valid_name()
    {
        ExecuteWithName("my-cert").ShouldBe(0);
    }

    [Theory]
    [InlineData("../../etc/passwd")]
    [InlineData("cert.crt")]
    [InlineData("1invalid")]
    public void Should_fail_for_invalid_names(string name)
    {
        ExecuteWithName(name).ShouldNotBe(0);
    }
}
