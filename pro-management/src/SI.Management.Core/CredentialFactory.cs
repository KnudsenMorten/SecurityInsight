using System.Security.Cryptography.X509Certificates;
using Azure.Core;
using Azure.Identity;

namespace SI.Management.Core;

/// Builds the one TokenCredential the process uses. Managed identity when hosted; a certificate from
/// LocalMachine\My (by thumbprint) when run locally. A client secret is not an option.
public static class CredentialFactory
{
    public static TokenCredential Create(IdentityOptions o)
    {
        ArgumentNullException.ThrowIfNull(o);
        if (string.Equals(o.Mode, "Certificate", StringComparison.OrdinalIgnoreCase))
        {
            if (string.IsNullOrWhiteSpace(o.TenantId) || string.IsNullOrWhiteSpace(o.ClientId) || string.IsNullOrWhiteSpace(o.CertificateThumbprint))
                throw new InvalidOperationException("Identity:Mode=Certificate needs TenantId, ClientId and CertificateThumbprint.");
            using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);
            var found = store.Certificates.Find(X509FindType.FindByThumbprint, o.CertificateThumbprint.Trim(), validOnly: false);
            var cert = found.Count > 0 ? found[0] : null;
            if (cert is null || !cert.HasPrivateKey)
                throw new InvalidOperationException("The configured certificate (with a private key) is not in LocalMachine\\My.");
            return new ClientCertificateCredential(o.TenantId, o.ClientId, cert);
        }
        if (string.Equals(o.Mode, "ManagedIdentity", StringComparison.OrdinalIgnoreCase) || string.IsNullOrWhiteSpace(o.Mode))
        {
            return string.IsNullOrWhiteSpace(o.ManagedIdentityClientId)
                ? new ManagedIdentityCredential(ManagedIdentityId.SystemAssigned)
                : new ManagedIdentityCredential(ManagedIdentityId.FromUserAssignedClientId(o.ManagedIdentityClientId));
        }
        throw new InvalidOperationException($"Identity:Mode must be ManagedIdentity or Certificate (got '{o.Mode}').");
    }
}
