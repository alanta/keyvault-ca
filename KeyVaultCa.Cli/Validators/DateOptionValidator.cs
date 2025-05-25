using System.ComponentModel.DataAnnotations;
using System.Globalization;
using McMaster.Extensions.CommandLineUtils;
using McMaster.Extensions.CommandLineUtils.Abstractions;
using McMaster.Extensions.CommandLineUtils.Validation;

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

public class DateOptionValidator : IOptionValidator
{
    public ValidationResult GetValidationResult(CommandOption option, ValidationContext context)
    {
        // This validator only runs if there is a value
        if (!option.HasValue()) return ValidationResult.Success!;
        
        var val = option.Value();

        if (string.IsNullOrWhiteSpace(val) || !DateTime.TryParse(val, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var parsed))
        {
            return new ValidationResult($"The value for option --{option.LongName} is not a valid UTC date time.");
        }

        return ValidationResult.Success!;
    }
}

public class DurationOptionValidator : IOptionValidator
{
    public ValidationResult GetValidationResult(CommandOption option, ValidationContext context)
    {
        // This validator only runs if there is a value
        if (!option.HasValue()) return ValidationResult.Success!;
        
        var val = option.Value();
        var valid = true;

        if (!string.IsNullOrWhiteSpace(val))
        {
            valid = TimeSpan.TryParse(val, CultureInfo.InvariantCulture, out _);
            if (!valid)
            {
                try
                {
                    System.Xml.XmlConvert.ToTimeSpan(val);
                    valid = true;
                }
                catch
                {
                    valid = false;
                }
            }
        }
        
        if( !valid )
        {
            return new ValidationResult($"The value for option --{option.LongName} is not a valid UTC date time.");
        }

        return ValidationResult.Success!;
    }
}

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
