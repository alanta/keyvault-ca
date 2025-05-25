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
}