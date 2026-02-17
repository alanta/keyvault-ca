using System;

namespace KeyVaultCa.Core
{
    /// <summary>
    /// Provides canonical normalization for certificate serial numbers.
    /// X509Certificate2.SerialNumber returns uppercase hex with leading zero bytes preserved
    /// (e.g., "00AB12CD"), while BouncyCastle BigInteger.ToString(16) strips leading zeros
    /// (e.g., "AB12CD"). This helper ensures a single canonical format is used everywhere:
    /// uppercase hex with leading zeros trimmed.
    /// </summary>
    public static class SerialNumberHelper
    {
        /// <summary>
        /// Normalizes a hex-encoded serial number to a canonical form:
        /// uppercase, leading zeros trimmed.
        /// </summary>
        /// <param name="hexSerial">Hex-encoded serial number (from X509Certificate2.SerialNumber,
        /// BigInteger.ToString(16), or user input)</param>
        /// <returns>Canonical serial: uppercase, no leading zeros (minimum "0")</returns>
        /// <exception cref="ArgumentNullException">If hexSerial is null</exception>
        public static string Normalize(string hexSerial)
        {
            ArgumentNullException.ThrowIfNull(hexSerial);

            var trimmed = hexSerial.TrimStart('0');

            if (trimmed.Length == 0)
            {
                return "0";
            }

            return trimmed.ToUpperInvariant();
        }
    }
}
