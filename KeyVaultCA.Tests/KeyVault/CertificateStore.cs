using Azure.Security.KeyVault.Certificates;
using FakeItEasy;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;

namespace KeyVaultCA.Tests.KeyVault;

public class CertificateStore
{
    private readonly List<CertificateVersion> _certificates = new();

    public IReadOnlyList<CertificateVersion> CertificateVersions => _certificates;

    public CertificateOperation StartOperation(string name, CertificatePolicy policy)
    {
        if (_certificates.Any(v => v.Name == name && !v.HasCompleted ))
            throw new InvalidOperationException($"Pending operation in progress on certificate {name}");

        var version = Guid.NewGuid().ToString("N");
        var item = new CertificateVersion
        {
            Name = name,
            Version = version,
            Policy = policy
        };

        _certificates.Add(item);

        CertificateRequest csr;

        // TODO : handle policy.ReuseKey
        // if (policy.ReuseKey == true)
        //    throw new NotImplementedException("ReuseKey is not implemented");

        if (policy.KeyType == CertificateKeyType.Ec)
        {
            var key = ECDsa.Create();
            csr = new CertificateRequest(new X500DistinguishedName(policy.Subject ?? "CN=Test"), key, HashAlgorithmName.SHA256);
        }
        else
        {
            var key = RSA.Create(policy.KeySize ?? 4096);
            csr = new CertificateRequest(new X500DistinguishedName(policy.Subject ?? "CN=Test"), key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        if (policy.SubjectAlternativeNames != null)
        {
            var sanBuilder = new SubjectAlternativeNameBuilder();
            foreach (var dnsName in policy.SubjectAlternativeNames.DnsNames)
            {
                sanBuilder.AddDnsName(dnsName);
            }

            foreach (var email in policy.SubjectAlternativeNames.Emails)
            {
                sanBuilder.AddEmailAddress(email);
            }

            foreach (var userPrincipalName in policy.SubjectAlternativeNames.UserPrincipalNames)
            {
                sanBuilder.AddUserPrincipalName(userPrincipalName);
            }
            
            csr.CertificateExtensions.Add(sanBuilder.Build());
        }

        if (policy.EnhancedKeyUsage != null && policy.EnhancedKeyUsage.Any())
        {
            var eku = new OidCollection();
            foreach (var oid in policy.EnhancedKeyUsage)
            {
                eku.Add(Oid.FromFriendlyName(oid, OidGroup.EnhancedKeyUsage));
            }
            csr.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(eku, false));
        }

        if (policy.KeyUsage.Any())
        {
            var ku = X509KeyUsageFlags.None;
            foreach (var flag in policy.KeyUsage)
            {
                if (flag == CertificateKeyUsage.CrlSign)
                    ku |= X509KeyUsageFlags.CrlSign;
                else if (flag == CertificateKeyUsage.DataEncipherment)
                    ku |= X509KeyUsageFlags.DataEncipherment;
                else if (flag == CertificateKeyUsage.DecipherOnly)
                    ku |= X509KeyUsageFlags.DecipherOnly;
                else if (flag == CertificateKeyUsage.DigitalSignature)
                    ku |= X509KeyUsageFlags.DigitalSignature;
                else if (flag == CertificateKeyUsage.EncipherOnly)
                    ku |= X509KeyUsageFlags.EncipherOnly;
                else if (flag == CertificateKeyUsage.KeyAgreement)
                    ku |= X509KeyUsageFlags.KeyAgreement;
                else if (flag == CertificateKeyUsage.KeyCertSign)
                    ku |= X509KeyUsageFlags.KeyCertSign;
                else if (flag == CertificateKeyUsage.KeyEncipherment)
                    ku |= X509KeyUsageFlags.KeyEncipherment;
                else if (flag == CertificateKeyUsage.NonRepudiation)
                    ku |= X509KeyUsageFlags.NonRepudiation;
                else
                    throw new ArgumentOutOfRangeException(nameof(flag), flag, null);
            }

            csr.CertificateExtensions.Add(new X509KeyUsageExtension(ku, true));
        }
        
        item.CertSigningRequest = csr.CreateSigningRequest();

        item.Properties = CertificateModelFactory.CertificateOperationProperties(
            name: name, 
            issuerName: policy.IssuerName,
            certificateType: policy.CertificateType,
            certificateTransparency: policy.CertificateTransparency,
            csr: item.CertSigningRequest);

        if (policy.IssuerName == "Self")
        {
            // immediately sign the certificate
            var cert = csr.CreateSelfSigned(DateTimeOffset.UtcNow, policy.ValidityInMonths != null ? DateTimeOffset.UtcNow.AddMonths( policy.ValidityInMonths.Value ) : DateTimeOffset.UtcNow.AddDays(7) );
            item.Certificate = cert.RawData;
        }

        return MapToModel(item);
    }

    public CertificateOperation? GetCertificateOperationById(string id)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(id));

        var cert = _certificates.FirstOrDefault(c => c.Version == id);


        return cert != null ? MapToModel(cert) : null;
    }

    private CertificateVersion? GetPendingOperationByName(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(name));

        return _certificates.FirstOrDefault(c => c.Name == name && !c.HasCompleted );
    }

    public CertificateOperation? GetCertificateOperationByName(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(name));

        var item = _certificates.FirstOrDefault(c => c.Name == name && !c.HasCompleted);

        return item != null ? MapToModel(item) : null;
    }

    public KeyVaultCertificateWithPolicy? GetCertificateByName(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(name));

        var cert = _certificates.LastOrDefault(c => c.Name == name && c.HasCompleted);

        return cert != null ? ToCertWithPolicyModel(cert.Name, cert.Version, cert.Policy, cert.Certificate) : null;
    }

    public KeyVaultCertificate? GetCertificateByNameAndVersion(string certName, string version)
    {
        if (string.IsNullOrWhiteSpace(certName))
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(certName));

        var cert = _certificates.LastOrDefault(c => c.Name == certName && c.Version == version);

        return cert != null ? ToCertModel(cert.Name, cert.Version, cert.Certificate) : null;
    }

    public IReadOnlyList<CertificateProperties> GetPropertiesOfCertificateVersionsByName(string certName)
    {
        if (string.IsNullOrWhiteSpace(certName))
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(certName));

        return _certificates.Where(c => c.Name == certName).Select(ToCertPropsModel).ToList();
    }

    private static CertificateProperties ToCertPropsModel(CertificateVersion cert)
    {
        var props = CertificateModelFactory.CertificateProperties(
            id: cert.Properties.Id, name: cert.Name, version: cert.Version );
        return props;
    }

    private static KeyVaultCertificate ToCertModel(string certName, string version, byte[]? rawBytes = null)
    {
        var props = CertificateModelFactory.CertificateProperties(id: new Uri($"https://localhost/certificates/{certName}/{version}"));
        var cert = CertificateModelFactory.KeyVaultCertificate(
            props,
            keyId: new Uri($"https://localhost/keys/{certName}/{version}"),
            secretId: new Uri($"https://localhost/secrets/{certName}/{version}"),
            cer: rawBytes);

        return cert;
    }

    private static KeyVaultCertificateWithPolicy ToCertWithPolicyModel(string certName, string version, CertificatePolicy? policy = null, byte[]? rawBytes = null)
    {
        var props = CertificateModelFactory.CertificateProperties(id: new Uri($"https://localhost/certificates/{certName}/{version}"));
        var cert = CertificateModelFactory.KeyVaultCertificateWithPolicy(
            props,
            keyId: new Uri($"https://localhost/keys/{certName}/{version}"),
            secretId: new Uri($"https://localhost/secrets/{certName}/{version}"),
            policy: policy ?? new CertificatePolicy { },
            cer: rawBytes);
        
        return cert;
    }

    public CertificateOperation Merge(string name, byte[] certRawData)
    {
        var cert = GetPendingOperationByName(name);
        if (cert == null)
        {
            throw new InvalidOperationException($"No pending operation in progress on certificate {name}");
        }

        cert.Certificate = certRawData;

        var certOperation = MapToModel(cert);
        return certOperation;
    }

    private static CertificateOperation MapToModel(CertificateVersion cert)
    {
        var certOperation = A.Fake<CertificateOperation>();
        A.CallTo(() => certOperation.Id).Returns(cert.Version);
        A.CallTo(() => certOperation.HasCompleted).Returns(cert.HasCompleted);
        A.CallTo(() => certOperation.Value).Returns(ToCertWithPolicyModel(cert.Name, cert.Version, cert.Policy, cert.Certificate));
        A.CallTo(() => certOperation.Properties).Returns(cert.Properties);
        return certOperation;
    }
}