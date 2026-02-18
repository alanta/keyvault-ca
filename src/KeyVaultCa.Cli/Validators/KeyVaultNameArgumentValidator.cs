using System.ComponentModel.DataAnnotations;
using KeyVaultCa.Core;
using McMaster.Extensions.CommandLineUtils;
using McMaster.Extensions.CommandLineUtils.Validation;

namespace KeyVaultCa.Cli.Validators;

public class KeyVaultNameArgumentValidator : IArgumentValidator
{
    public ValidationResult GetValidationResult(CommandArgument argument, ValidationContext context)
    {
        var value = argument.Value;
        if (value is null) return ValidationResult.Success!;

        if (!KeyVaultSecretReference.IsValidCertificateName(value))
        {
            return new ValidationResult(
                $"'{value}' is not a valid Key Vault certificate name. " +
                "Names must be 1-127 characters, start with a letter, and contain only letters, digits, and hyphens.");
        }

        return ValidationResult.Success!;
    }
}
