using System.ComponentModel.DataAnnotations;
using System.Globalization;
using McMaster.Extensions.CommandLineUtils;
using McMaster.Extensions.CommandLineUtils.Validation;

namespace KeyVaultCa.Cli.Validators;

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