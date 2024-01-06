using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Azure;
using Azure.Security.KeyVault.Certificates;
using Xunit.Sdk;

namespace KeyVaultCA.Tests.KeyVault
{
    public class KeyVaultCertificateTestHarness : CertificateClient
    {
        public override Response<byte[]> BackupCertificate(string certificateName, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public override Task<Response<byte[]>> BackupCertificateAsync(string certificateName, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public override Response<X509Certificate2> DownloadCertificate(string certificateName, string? version = null, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public override Task<Response<X509Certificate2>> DownloadCertificateAsync(string certificateName, string? version = null, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public override Response<KeyVaultCertificateWithPolicy> GetCertificate(string certificateName, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public override CertificateOperation StartCreateCertificate(string certificateName, CertificatePolicy policy, bool? enabled = null,
            IDictionary<string, string> tags = null, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public override Task<CertificateOperation> StartCreateCertificateAsync(string certificateName, CertificatePolicy policy, bool? enabled = null,
            IDictionary<string, string> tags = null, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public override CertificateOperation GetCertificateOperation(string certificateName,
            CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public override Task<CertificateOperation> GetCertificateOperationAsync(string certificateName,
            CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public override Task<Response<KeyVaultCertificateWithPolicy>> GetCertificateAsync(string certificateName, CancellationToken cancellationToken = new CancellationToken())
        {
            throw new NotEmptyException();
        }
    }
}
