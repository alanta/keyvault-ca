using System.Globalization;
using McMaster.Extensions.CommandLineUtils.Abstractions;

namespace KeyVaultCa.Cli.Validators;

public class TimeSpanValueParser : IValueParser<TimeSpan>
{
    object? IValueParser.Parse(string? argName, string? value, CultureInfo culture)
    {
        return Parse(argName, value, culture);
    }

    public TimeSpan Parse(string? argName, string? value, CultureInfo culture)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(value));
        }

        if (!TimeSpan.TryParse(value, culture, out var result))
        {
            // Fallback to XmlConvert if parsing fails
            try
            {
                result = System.Xml.XmlConvert.ToTimeSpan(value);
            }
            catch (FormatException ex)
            {
                throw new ArgumentException($"The value '{value}' for argument '{argName}' is not a valid TimeSpan. It must be formatted as DD:hh:mm:ss or ISO 8601, for example P90D for 90 days.", nameof(value), ex);
            }
        }

        return result;

    }

    public Type TargetType => typeof(TimeSpan);
}