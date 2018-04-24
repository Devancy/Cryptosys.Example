using System;
using CryptoSysPKI;

namespace Cryptosys.Example
{
    class Program
    {
        // https://www.cryptosys.net/pki/rsakeyformats.html
        static void Main(string[] args)
        {
            Console.WriteLine("CryptoSys PKI Version={0}", General.Version());
            V_Test_RSA_MakeKeys();
            V_Test_X509_MakeCertSelf();
            V_Test_X509_MakeCert();
            Console.WriteLine("Done.");
            Console.ReadKey();

        }
        public static void V_Test_RSA_MakeKeys()
        {
            Console.WriteLine("Testing RSA_MakeKeys ...");
            int nRet = 0;
            string sPublicKeyFile = null;
            string sPrivateKeyFile = null;
            string sPassword = null;

            sPublicKeyFile = "myca.pub";
            sPrivateKeyFile = "myca.epk";
            sPassword = "password";

            // Create a new pair of RSA keys saved as BER-encoded files
            Console.WriteLine("About to create a new RSA key pair...");

            nRet = Rsa.MakeKeys(sPublicKeyFile, sPrivateKeyFile, 512, Rsa.PublicExponent.Exp_EQ_3, 1000, sPassword, Rsa.PbeOptions.PbeWithMD5AndDES_CBC, false);

            Console.WriteLine("RSA_MakeKeys returns " + nRet + " (expected 0)");

        }
        public static void V_Test_X509_MakeCertSelf()
        {
            Console.WriteLine("Testing X509_MakeCertSelf ...");
            int nRet = 0;
            X509.KeyUsageOptions kuoKeyUsage = default(X509.KeyUsageOptions);

            kuoKeyUsage = X509.KeyUsageOptions.DigitalSignature | X509.KeyUsageOptions.KeyCertSign | X509.KeyUsageOptions.CrlSign;
            nRet = X509.MakeCertSelf("myca.cer", "myca.epk", 99, 10, "CN=My CA,O=Test Org,OU=Certificate Services", "", kuoKeyUsage, "password", 0);
            if (nRet != 0)
            {
                Console.WriteLine(nRet + " " + General.LastError());
            }
            else
            {
                Console.WriteLine("Success");
            }

        }
        public static void V_Test_X509_MakeCert()
        {
            Console.WriteLine("Testing X509_MakeCert ...");
            int nRet = 0;
            string strNewCertFile = null;
            string strIssuerCert = null;
            string strSubjectPubKeyFile = null;
            string strIssuerPriKeyFile = null;
            string strPassword = null;
            int nCertNum = 0;
            int nYearsValid = 0;
            string strDistName = null;
            string strEmail = null;
            strNewCertFile = "myuser.cer";
            strIssuerCert = "myca.cer";
            strSubjectPubKeyFile = "myca.pub";
            strIssuerPriKeyFile = "myca.epk";
            strPassword = "password";
            //!!
            nCertNum = 0x101;
            nYearsValid = 4;
            strDistName = "CN=My User,O=Test Org,OU=Unit,C=AU,L=My Town,S=State,E=myuser@testorg.com";
            strEmail = "myuser@testorg.com";

            nRet = X509.MakeCert(strNewCertFile, strIssuerCert, strSubjectPubKeyFile, strIssuerPriKeyFile, nCertNum, nYearsValid, strDistName, strEmail, 0, strPassword,
                0);
            if (nRet != 0)
            {
                Console.WriteLine(nRet + " " + General.LastError());
            }
            else
            {
                Console.WriteLine("Success, created X.509 cert " + strNewCertFile);
            }

        }
        public static void V_Test_X509_CertRequest()
        {
            Console.WriteLine("Testing X509_CertRequest ...");
            int nRet = 0;
            nRet = X509.CertRequest("myreq.p10.txt", "mykey.epk", "CN=myuser,O=Test Org,C=AU,L=Sydney,S=NSW", "password", 0);
            if (nRet != 0)
            {
                Console.WriteLine(nRet + " " + General.LastError());
            }
            else
            {
                Console.WriteLine("Success");
            }

        }
    }
}
