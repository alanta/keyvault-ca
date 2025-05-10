using System.ComponentModel.DataAnnotations;
using System.Globalization;
using McMaster.Extensions.CommandLineUtils;
using McMaster.Extensions.CommandLineUtils.Validation;

namespace KeyVaultCa.Cli.Validatiors;

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

        if (string.IsNullOrWhiteSpace(val) || !TimeSpan.TryParse(val, CultureInfo.InvariantCulture, out var parsed))
        {
            return new ValidationResult($"The value for option --{option.LongName} is not a valid UTC date time.");
        }

        return ValidationResult.Success!;
    }
}
