using System.Globalization;
using Azure.Security.KeyVault.Certificates;
using KeyVaultCa.Cli.Validators;
using McMaster.Extensions.CommandLineUtils;

namespace KeyVaultCa.Cli.Handlers;

public static class CommonOptions
{
    public static CommandOption<TimeSpan> AddDurationOption(this CommandLineApplication app)
    {
        return app.Option<TimeSpan>("--duration", "The duration of the certificate in days. Default is 365 days.",
                CommandOptionType.SingleValue)
            .AcceptsDuration();
    }

    public static CommandOption<DateTime> AddNotBeforeOption(this CommandLineApplication app)
    {
        return app.Option<DateTime>("--not-before",
                "The date and time the certificate becomes valid. Defaults to current date and time.",
                CommandOptionType.SingleValue)
            .AcceptsUtcDate();
    }

    public static CommandOption<DateTime> AddNotAfterOption(this CommandLineApplication app)
    {
        return app.Option<DateTime>("--not-after",
                "The date and time until which the certificate is valid. Defaults to current date and time + 1 year",
                CommandOptionType.SingleValue)
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
            ? durationOption.ParsedValue
            : defaultDuration;

        var notAfter = notAfterOption.HasValue()
            ? DateTime.TryParse(notAfterOption.Value()!, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed2)
                ? parsed2
                : notBefore + duration
            : notBefore + duration;

        return (notBefore, notAfter);
    }

    public static CommandOption<string> AddDnsOption(this CommandLineApplication app)
    {
        return app.Option<string>("-d|--dns <DNS_NAME>", "A DNS name for the certificate to add as Subject Alternative Name (SAN). Can be specified multiple times.", CommandOptionType.MultipleValue);
    }
    
    public static CommandOption<string> AddEmailOption(this CommandLineApplication app)
    {
        return app.Option<string>("-e|--email <EMAIL_ADDRESS>", "An email address for the certificate to add as Subject Alternative Name (SAN). Can be specified multiple times.", CommandOptionType.MultipleValue);
    }
    
    public static CommandOption<string> AddUpnOption(this CommandLineApplication app)
    {
        return app.Option<string>("-u|--upn <UPN>", "A user principal name for the certificate to add as Subject Alternative Name (SAN). Can be specified multiple times.", CommandOptionType.MultipleValue);
    }
    
    public static SubjectAlternativeNames ParseSubjectAlternativeNames(
        CommandOption dnsOption,
        CommandOption emailOption,
        CommandOption upnOption)
    {
        var san = new SubjectAlternativeNames();

        foreach (var optionValue in dnsOption.Values)
        {
            san.DnsNames.Add(optionValue);
        }

        foreach (var optionValue in emailOption.Values)
        {
            san.Emails.Add(optionValue);
        }

        foreach (var optionValue in upnOption.Values)
        {
            san.UserPrincipalNames.Add(optionValue);
        }

        return san;
    }
}