using System.Security.Cryptography;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;

namespace KeyVaultCa.Core;

public static class ObjectIdentifierExtensions
{
    public static bool IsEllipticCurveKey(this Oid? oid)
    {
        return oid != null && new DerObjectIdentifier(oid.Value).On(X9ObjectIdentifiers.ansi_X9_62);
    }

    public static bool IsDiffieHellmanKey(this Oid? oid)
    {
        return oid!=null && new DerObjectIdentifier(oid.Value).On(X9ObjectIdentifiers.DHPublicNumber);
    }
}