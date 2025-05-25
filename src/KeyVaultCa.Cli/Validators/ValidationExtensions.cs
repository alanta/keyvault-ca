using McMaster.Extensions.CommandLineUtils;

namespace KeyVaultCa.Cli.Validators;

public static class ValidationExtensions
{
    public static CommandOption<DateTime> AcceptsUtcDate(this CommandOption<DateTime> option)
    {
        option.Validators.Add(new DateOptionValidator());
        return option;
    }
    
    public static CommandOption<TimeSpan> AcceptsDuration(this CommandOption<TimeSpan> option)
    {
        option.Validators.Add(new DurationOptionValidator());
        return option;
    }
}