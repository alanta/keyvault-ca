namespace KeyVaultCa.Revocation.Models;

/// <summary>
/// Certificate revocation reasons as defined in RFC 5280 section 5.3.1
/// </summary>
public enum RevocationReason
{
    /// <summary>
    /// No specific reason provided
    /// </summary>
    Unspecified = 0,

    /// <summary>
    /// The private key has been compromised
    /// </summary>
    KeyCompromise = 1,

    /// <summary>
    /// The CA's private key has been compromised
    /// </summary>
    CACompromise = 2,

    /// <summary>
    /// The subject's affiliation with the organization has changed
    /// </summary>
    AffiliationChanged = 3,

    /// <summary>
    /// The certificate has been superseded by a new one
    /// </summary>
    Superseded = 4,

    /// <summary>
    /// The certificate is no longer needed
    /// </summary>
    CessationOfOperation = 5,

    /// <summary>
    /// The certificate is on hold (temporary suspension)
    /// </summary>
    CertificateHold = 6,

    // Note: 7 is not used in RFC 5280

    /// <summary>
    /// Remove the certificate from the CRL (only for delta CRLs)
    /// </summary>
    RemoveFromCRL = 8,

    /// <summary>
    /// The privilege granted by this certificate has been withdrawn
    /// </summary>
    PrivilegeWithdrawn = 9,

    /// <summary>
    /// The AA's private key has been compromised
    /// </summary>
    AACompromise = 10
}
