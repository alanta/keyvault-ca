using System.Collections.ObjectModel;
using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using KeyVaultCa.Core;

namespace KeyVaultCA.Tests.Core;

public class When_merging_extensions
{
    [Fact]
    public void It_should_replace_basic_constraints()
    {
        // Arrange
        Collection<X509Extension> request =
        [
            new X509BasicConstraintsExtension(false, false, 0, false),
        ];
        
        Collection<X509Extension> overrideExtensions =
        [
            // This is used to create intermediate certificates
            new X509BasicConstraintsExtension(true, true, 1, true),
        ];

        // Act
        CertificateFactory.MergeExtensions(request, overrideExtensions);

        // Assert
        var basicConstraints = request.OfType<X509BasicConstraintsExtension>().Single();
        basicConstraints.CertificateAuthority.Should().BeTrue();
        basicConstraints.HasPathLengthConstraint.Should().BeTrue();
        basicConstraints.PathLengthConstraint.Should().Be(1);
    }
    
    [Fact]
    public void It_should_replace_key_usage()
    {
        // Arrange
        Collection<X509Extension> request =
        [
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false),
        ];
        
        Collection<X509Extension> overrideExtensions =
        [
            new X509KeyUsageExtension(X509KeyUsageFlags.CrlSign, true),
        ];

        // Act
        CertificateFactory.MergeExtensions(request, overrideExtensions);

        // Assert
        var keyUsage = request.OfType<X509KeyUsageExtension>().Single();
        keyUsage.KeyUsages.Should().Be(X509KeyUsageFlags.CrlSign);
    }
    
    [Fact]
    public void It_should_replace_all_subject_alternative_names()
    {
        // Arrange
        var builder = new SubjectAlternativeNameBuilder();
        builder.AddDnsName("test.alanta.local");
        builder.AddEmailAddress("test@alanta.nl");
        var requestSan = builder.Build(true);
        Collection<X509Extension> request = [
            new X509BasicConstraintsExtension(false, false, 0, false),
            new X509SubjectAlternativeNameExtension(requestSan.RawData, requestSan.Critical)
        ];
        
        builder = new SubjectAlternativeNameBuilder();
        builder.AddDnsName("test2.alanta.local");
        var overrideSan = builder.Build(true);
        Collection<X509Extension> overrideExtensions = [
            new X509SubjectAlternativeNameExtension(overrideSan.RawData, overrideSan.Critical)
        ];

        // Act
        CertificateFactory.MergeExtensions(request, overrideExtensions);

        // Assert
        request.Should().HaveCount(2);
        var subjectAlternativeName = request.OfType<X509SubjectAlternativeNameExtension>().Single();
        subjectAlternativeName.EnumerateDnsNames().Should().Contain("test2.alanta.local");

        var basicConstraints = request.OfType<X509BasicConstraintsExtension>().FirstOrDefault()
            .Should().NotBeNull("Basic constraints should be preserved");
    }
}