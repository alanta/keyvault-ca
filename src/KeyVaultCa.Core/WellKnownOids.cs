namespace KeyVaultCa.Core;

public static class WellKnownOids
{
    public static class ExtendedKeyUsages
    {
        // source: https://oidref.com/1.3.6.1.5.5.7.3
        public const string ServerAuth = "1.3.6.1.5.5.7.3.1";
        public const string ClientAuth = "1.3.6.1.5.5.7.3.2";
        public const string CodeSigning = "1.3.6.1.5.5.7.3.3";
        public const string EmailProtection = "1.3.6.1.5.5.7.3.4";
        public const string IpSecEndSystem = "1.3.6.1.5.5.7.3.5";
        public const string IpSecTunnel = "1.3.6.1.5.5.7.3.6";
        public const string IpSecUser = "1.3.6.1.5.5.7.3.7";
        public const string TimeStamping = "1.3.6.1.5.5.7.3.8";
        public const string OCSPSigning = "1.3.6.1.5.5.7.3.9";
    }

    public static class Extensions
    {
        /// <summary>
        /// Authority Information Access (AIA) - RFC 5280 section 4.2.2.1
        /// </summary>
        public const string AuthorityInformationAccess = "1.3.6.1.5.5.7.1.1";

        /// <summary>
        /// CRL Distribution Points (CDP) - RFC 5280 section 4.2.1.13
        /// </summary>
        public const string CrlDistributionPoints = "2.5.29.31";
    }

    public static class AccessMethods
    {
        /// <summary>
        /// OCSP access method - RFC 5280 section 4.2.2.1
        /// </summary>
        public const string Ocsp = "1.3.6.1.5.5.7.48.1";

        /// <summary>
        /// CA Issuers access method - RFC 5280 section 4.2.2.1
        /// </summary>
        public const string CaIssuers = "1.3.6.1.5.5.7.48.2";
    }
}