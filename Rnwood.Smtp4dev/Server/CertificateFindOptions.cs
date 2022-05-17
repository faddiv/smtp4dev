using System.Security.Cryptography.X509Certificates;

namespace Rnwood.Smtp4dev.Server
{
    public class CertificateFindOptions
    {
        public string StoreName { get; set; } = "My";
        public StoreLocation StoreLocation { get; set; } = StoreLocation.LocalMachine;
        public X509FindType X509FindType { get; set; } = X509FindType.FindBySerialNumber;
        public string FindValue { get; set; } = null;
    }
}
