using FluentAssertions;
using KeyVaultCa.Core;

namespace KeyVaultCA.Tests.Core;

public class When_handling_keyvault_secret_references
{
    [Theory]
    [InlineData("https://myvault.vault.azure.net/secrets/mysecret", "https://myvault.vault.azure.net", "mysecret")]
    [InlineData("https://ca.vault.azure.net/certificates/mycert", "https://ca.vault.azure.net", "mycert")]
    [InlineData("mysecret@myvault", "https://myvault.vault.azure.net", "mysecret")]
    public void It_should_parse_valid_keyvault_secret_references(string input, string expectedVault, string expectedSecret)
    {
        // Arrange & Act
        var result = KeyVaultSecretReference.TryParse(input, out var reference);
        // Assert
        result.Should().BeTrue();
        reference!.KeyVaultUrl.Should().Be(expectedVault);
        reference.SecretName.Should().Be(expectedSecret);
    }
    
    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("invalidreference")]
    [InlineData("https://myvault.vault.azure.net/badformat")]
    public void It_should_fail_to_parse_invalid_keyvault_secret_references(string? input)
    {
        // Arrange & Act
        var result = KeyVaultSecretReference.TryParse(input!, out var reference);
        // Assert
        result.Should().BeFalse();
        reference.Should().BeNull();
    }
}