using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Casttle;
using Org.BouncyCastle.Security;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace Cryptosys.Example
{
    public class Test
    {
        private const string CARootPfx = @"D:\rootCert.pfx";
        private const string CARootCer = @"D:\rootCert.cer";
        private const string CARoot2Pfx = @"D:\root2Cert.pfx";
        private const string CARoot2Cer = @"D:\root2Cert.cer";
        private const string PIN = "1";
        private const string CAUserPfx = @"D:\userCert.pfx";
        private const string CAUserCer = @"D:\userCert.cer";
        private const string CAUser2Pfx = @"D:\user2Cert.pfx";
        private const string CAUser2Cer = @"D:\user2Cert.cer";

        public static string CreateCARoot()
        {
            var caRoot = Cert2.CreateCertificateAuthorityCertificate("MyRootCA");
            var add = Cert2.AddCertToStore(caRoot, StoreName.Root, StoreLocation.LocalMachine);
            byte[] caRootPfx = caRoot.Export(X509ContentType.Pfx, PIN);
            File.WriteAllBytes(CARootPfx, caRootPfx);
            byte[] caRootCer = caRoot.Export(X509ContentType.Cert, PIN);
            File.WriteAllBytes(CARootCer, caRootCer);
            return CARootPfx;
        }
        public static string CreateCARoot2()
        {
            var caRoot = Cert2.CreateCertificateAuthorityCertificate("MyRootCA2");
            byte[] caRootPfx = caRoot.Export(X509ContentType.Pfx, PIN);
            File.WriteAllBytes(CARoot2Pfx, caRootPfx);
            byte[] caRootCer = caRoot.Export(X509ContentType.Cert, PIN);
            File.WriteAllBytes(CARoot2Cer, caRootCer);
            return CARootPfx;
        }

        public static string CreateCAUser()
        {
            X509Certificate2 cert = new X509Certificate2(CARootPfx, PIN, X509KeyStorageFlags.Exportable);
            var rootKeyPair = Cert2.ReadPrivateKey(cert);
            var userCert = Cert2.CreateSelfSignedCertificate("CN=MyUserCA", "CN=MyROOTCA", rootKeyPair);
            //File.WriteAllText(@"D:\PrivateKey.xml", userCert.PrivateKey.ToXmlString(true));
            //File.WriteAllText(@"D:\PublicKey.xml", userCert.PublicKey.Key.ToXmlString(false));
            byte[] caUserCer = userCert.Export(X509ContentType.Cert, PIN);
            File.WriteAllBytes(CAUserCer, caUserCer);
            byte[] caUserPfx = userCert.Export(X509ContentType.Pfx, PIN);
            File.WriteAllBytes(CAUserPfx, caUserPfx);
            return CAUserPfx;
        }
        public static string CreateCAUser2()
        {
            X509Certificate2 cert = new X509Certificate2(CARootPfx, PIN, X509KeyStorageFlags.Exportable);
            var rootKeyPair = Cert2.ReadPrivateKey(cert);
            var userCert = Cert2.CreateSelfSignedCertificate("CN=MyUser2CA", "CN=MyROOTCA", rootKeyPair);
            //File.WriteAllText(@"D:\PrivateKey.xml", userCert.PrivateKey.ToXmlString(true));
            //File.WriteAllText(@"D:\PublicKey.xml", userCert.PublicKey.Key.ToXmlString(false));
            byte[] caUserCer = userCert.Export(X509ContentType.Cert, PIN);
            File.WriteAllBytes(CAUser2Cer, caUserCer);
            byte[] caUserPfx = userCert.Export(X509ContentType.Pfx, PIN);
            File.WriteAllBytes(CAUser2Pfx, caUserPfx);
            return CAUserPfx;
        }

        public static void RootVerifyUserCA()
        {
            try
            {
                X509Certificate2 userCert2 = new X509Certificate2(CAUserPfx, PIN, X509KeyStorageFlags.Exportable);
                X509Certificate userCert = DotNetUtilities.FromX509Certificate(userCert2);
                userCert2.p
                var userKeyPair = userCert.GetPublicKey();
                //var publicKey = userCert2.PublicKey;
                X509Certificate2 rootCert2 = new X509Certificate2(CARootPfx, PIN, X509KeyStorageFlags.Exportable);
                //var rootKeyPair = Cert2.ReadPrivateKey(rootCert2);
                var add = Cert2.AddCertToStore(rootCert2, StoreName.Root, StoreLocation.LocalMachine);
                var rootCert = DotNetUtilities.FromX509Certificate(userCert2);
                var rootKeyPair = rootCert.GetPublicKey();

                //rootCert.Verify(userKeyPair);
                var a = Cert2.VerifySha2(rootCert2, userCert.GetEncoded(), userCert.GetSignature());
            }
            catch (Exception ex)
            {

                //throw;
            }
        }
        public static void Root2VerifyUserCA()
        {
            try
            {
                X509Certificate2 userCert2 = new X509Certificate2(CAUserPfx, PIN, X509KeyStorageFlags.Exportable);
                var userCert = DotNetUtilities.FromX509Certificate(userCert2);
                var publicKey = userCert.GetPublicKey();
                //var publicKey = userCert2.PublicKey;
                X509Certificate2 root2Cert2 = new X509Certificate2(CARoot2Pfx, PIN, X509KeyStorageFlags.Exportable);
                var root2KeyPair = Cert2.ReadPrivateKey(root2Cert2);

                userCert.Verify(root2KeyPair);
            }
            catch (Exception ex)
            {

                //throw;
            }
        }

        public static bool VerifyCertificate()
        {
            X509Certificate2 primaryCert = new X509Certificate2(CARootPfx, PIN, X509KeyStorageFlags.Exportable);
            var root = primaryCert.Verify(); // true = installed
            X509Certificate2 userCert = new X509Certificate2(CAUserPfx, PIN, X509KeyStorageFlags.Exportable);
            X509Certificate2 userCert2 = new X509Certificate2(CAUser2Pfx, PIN, X509KeyStorageFlags.Exportable);
            var additionalCertificates = new List<X509Certificate2> { userCert, userCert2 };
            return Cert2.VerifyCertificate(primaryCert, additionalCertificates);

        }

        
    }
}
