using KeyVaultCa.Core;
using Shouldly;

namespace KeyVaultCa.Tests.Core;

public class When_validating_keyvault_certificate_names
{
    [Theory]
    [InlineData("a")]
    [InlineData("A")]
    [InlineData("my-cert")]
    [InlineData("MyCert")]
    [InlineData("my-cert-123")]
    [InlineData("RootCA")]
    [InlineData("intermediate-ca-2")]
    public void Should_accept_valid_names(string name)
    {
        KeyVaultSecretReference.IsValidCertificateName(name).ShouldBeTrue();
    }

    [Fact]
    public void Should_accept_a_127_character_name()
    {
        var name = "A" + new string('a', 126);
        name.Length.ShouldBe(127);
        KeyVaultSecretReference.IsValidCertificateName(name).ShouldBeTrue();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Should_reject_null_or_empty(string? name)
    {
        KeyVaultSecretReference.IsValidCertificateName(name).ShouldBeFalse();
    }

    [Theory]
    [InlineData("1cert")]          // starts with digit
    [InlineData("-cert")]          // starts with hyphen
    [InlineData("cert.crt")]       // contains dot
    [InlineData("cert/name")]      // contains slash
    [InlineData("cert\\name")]     // contains backslash
    [InlineData("cert name")]      // contains space
    [InlineData("cert@vault")]     // contains @
    public void Should_reject_names_with_invalid_characters(string name)
    {
        KeyVaultSecretReference.IsValidCertificateName(name).ShouldBeFalse();
    }

    [Theory]
    [InlineData("../../etc/passwd")]
    [InlineData("../secrets")]
    [InlineData("..\\windows\\system32")]
    [InlineData("/etc/passwd")]
    [InlineData("C:\\Windows\\System32\\cert")]
    public void Should_reject_path_traversal_strings(string name)
    {
        KeyVaultSecretReference.IsValidCertificateName(name).ShouldBeFalse();
    }

    [Fact]
    public void Should_reject_a_128_character_name()
    {
        var name = "A" + new string('a', 127);
        name.Length.ShouldBe(128);
        KeyVaultSecretReference.IsValidCertificateName(name).ShouldBeFalse();
    }
}
