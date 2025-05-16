using System.Globalization;
using KeyVaultCa.Cli.Validatiors;
using McMaster.Extensions.CommandLineUtils;

namespace KeyVaultCa.Cli.Handlers;

public static class CommonOptions
{
    public static CommandOption<TimeSpan> AddDurationOption(this CommandLineApplication app)
    {
        return app.Option<TimeSpan>("--duration", "The duration of the certificate in days. Default is 365 days.", CommandOptionType.SingleValue)
            .AcceptsDuration();
    }
    
    public static CommandOption<DateTime> AddNotBeforeOption(this CommandLineApplication app)
    {
        return app.Option<DateTime>("--not-before", "The date and time the certificate becomes valid. Defaults to current date and time.", CommandOptionType.SingleValue)
            .AcceptsUtcDate();
    }
    
    public static CommandOption<DateTime> AddNotAfterOption(this CommandLineApplication app)
    {
        return app.Option<DateTime>("--not-after", "The date and time until which the certificate is valid. Defaults to current date and time + 1 year", CommandOptionType.SingleValue)
            .AcceptsUtcDate();
    }

    public static (DateTimeOffset notBefore, DateTimeOffset notAfter) DetermineValidityPeriod(
        CommandOption<DateTime> notBeforeOption,
        CommandOption<DateTime> notAfterOption,
        CommandOption<TimeSpan> durationOption,
        TimeSpan defaultDuration)
    {
        var notBefore = notBeforeOption.HasValue()
            ? DateTime.TryParse(notBeforeOption.Value()!, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed)
                ? parsed
                : DateTimeOffset.UtcNow
            : DateTime.UtcNow;

        var duration = durationOption.HasValue()
            ? TimeSpan.TryParse(durationOption.Value()!, CultureInfo.InvariantCulture, out var parsed3)
                ? parsed3
                : defaultDuration
            : defaultDuration;

        var notAfter = notAfterOption.HasValue()
            ? DateTime.TryParse(notAfterOption.Value()!, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed2)
                ? parsed2
                : notBefore + duration
            : notBefore + duration;

        return (notBefore, notAfter);
    }
}