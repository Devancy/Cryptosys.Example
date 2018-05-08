using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Casttle;
using CryptoSysPKI;
using Org.BouncyCastle.Crypto;

namespace Cryptosys.Example
{
    class Program
    {
        // https://www.cryptosys.net/pki/rsakeyformats.html
        static void Main(string[] args)
        {
            //Cert.Do();
            //var rootCA = Test.CreateCARoot();
            //var userCA = Test.CreateCAUser();
            //Test.CreateCAUser2();
            //Test.CreateCARoot2();
            //Test.RootVerifyUserCA();
            //Test.Root2VerifyUserCA();
            //var nRet = X509.VerifyCert(@"D:\userCert.cer", @"D:\rootCert.cer");
            
            Test.VerifyCertificate();


            //Console.WriteLine("CryptoSys PKI Version={0}", General.Version());
            // TODO Create CA
            //V_Test_RSA_MakeKeys();
            //V_Test_X509_MakeCertSelf();

            // TODO Create user
            //V_Test_RSA_MakeUserKeys();
            //V_Test_X509_MakeCert();

            //V_Test_PFX_MakeFile();
            //V_Test_RSA_PublicKeyFromPrivate();
            //V_Test_X509_VerifyCert();
            //V_Test_X509_CertIsValidNow();
            //V_Test_X509_CertExpiresOn();
            //V_Test_CMS_MakeSigData();
            //V_Test_CMS_VerifySigData();




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

            nRet = Rsa.MakeKeys(sPublicKeyFile, sPrivateKeyFile, 512, Rsa.PublicExponent.Exp_EQ_3, 1000, sPassword, Rsa.PbeOptions.PbeWithSHAAnd_KeyTripleDES_CBC, false);

            Console.WriteLine("RSA_MakeKeys returns " + nRet + " (expected 0)");

        }
        public static void V_Test_RSA_MakeUserKeys()
        {
            Console.WriteLine("Testing RSA_MakeUserKeys ...");
            int nRet = 0;
            string sPublicKeyFile = null;
            string sPrivateKeyFile = null;
            string sPassword = null;

            sPublicKeyFile = "myuser.pub";
            sPrivateKeyFile = "myuser.epk";
            sPassword = "password";

            // Create a new pair of RSA keys saved as BER-encoded files
            Console.WriteLine("About to create a new RSA key pair...");

            nRet = Rsa.MakeKeys(sPublicKeyFile, sPrivateKeyFile, 512, Rsa.PublicExponent.Exp_EQ_3, 1000, sPassword, Rsa.PbeOptions.PbeWithSHAAnd_KeyTripleDES_CBC, false);

            Console.WriteLine("RSA_MakeUserKeys returns " + nRet + " (expected 0)");

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
            strSubjectPubKeyFile = "myuser.pub";
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
        public static void V_Test_RSA_PublicKeyFromPrivate()
        {
            Console.WriteLine("Testing RSA_PublicKeyFromPrivate ...");
            string strPriKeyFile = null;
            StringBuilder sbPrivateKey = null;
            string strPublicKey = null;
            int nCode = 0;
            int nRet = 0;

            // Read private key from encrypted private key file into internal string form
            strPriKeyFile = "myuser.epk";
            sbPrivateKey = Rsa.ReadEncPrivateKey(strPriKeyFile, "password");
            if (sbPrivateKey.Length == 0) return;

            //Catch error here
            // Display some info about it
            Console.WriteLine("Private key length = {0} bits", Rsa.KeyBits(sbPrivateKey.ToString()));
            nCode = Rsa.KeyHashCode(sbPrivateKey.ToString());
            Console.WriteLine("KeyHashCode={0,8:X}", nCode);
            nRet = Rsa.CheckKey(sbPrivateKey);
            Console.WriteLine("Rsa.CheckKey returns " + nRet + ": (PKI_VALID_PRIVATEKEY=" + 0 + ")");

            // Convert to public key string
            strPublicKey = Rsa.PublicKeyFromPrivate(sbPrivateKey).ToString();
            if (strPublicKey.Length == 0) return;

            // Catch error here
            // Display some info about it
            Console.WriteLine("Public key length = " + Rsa.KeyBits(strPublicKey) + " bits");
            nCode = Rsa.KeyHashCode(strPublicKey);
            Console.WriteLine("KeyHashCode={0,8:X}", nCode);
            nRet = Rsa.CheckKey(strPublicKey);
            Console.WriteLine("Rsa.CheckKey returns " + nRet + ": (PKI_VALID_PUBLICKEY=" + 1 + ")");

            // Clean up
            Wipe.String(sbPrivateKey);

        }
        public static void V_Test_PFX_MakeFile()
        {
            Console.WriteLine("Testing PFX_MakeFile ...");
            string strOutputFile = null;
            string strCertFile = null;
            string strKeyFile = null;
            StringBuilder sbPassword = null;
            int nRet = 0;
            bool isOK = false;

            strOutputFile = "myuser.pfx";
            strCertFile = "myuser.cer";
            strKeyFile = "myuser.epk";
            sbPassword = new StringBuilder("password");

            // Given Bob's certificate and encrypted private key file (with password "password"),
            // create a PKCS-12 (pfx/p12) file.
            nRet = Pfx.MakeFile(strOutputFile, strCertFile, strKeyFile, sbPassword.ToString(), "CA's ID", Pfx.Options.Default);
            Console.WriteLine("Pfx.MakeFile returns " + nRet);

            // Now verify that the signature is OK
            isOK = Pfx.SignatureIsValid(strOutputFile, sbPassword.ToString());
            Console.WriteLine("Pfx.SignatureIsValid returns " + isOK);

            // Clean up
            Wipe.String(sbPassword);

        }
        public static void V_Test_X509_VerifyCert()
        {
            Console.WriteLine("Testing X509_VerifyCert ...");
            // Returns 0 if OK, -1 if fails to validate, or +ve other error
            int nRet = 0;
            nRet = X509.VerifyCert("myuser.cer", "myca.cer");
            if (nRet == 0)
            {
                Console.WriteLine("Verification is OK");
            }
            else if (nRet > 0)
            {
                Console.WriteLine("Error: " + nRet + General.LastError());
            }
            else
            {
                Console.WriteLine("Cert not issued by this Issuer");
            }

        }
        public static void V_Test_X509_CertIsValidNow()
        {
            Console.WriteLine("Testing X509_CertIsValidNow ...");
            bool isValid = false;
            string strCertName = null;

            strCertName = "myuser.cer";
            isValid = X509.CertIsValidNow(strCertName);
            Console.WriteLine("X509_CertIsValidNow returns " + isValid + " for " + strCertName);

        }
        public static void V_Test_X509_CertExpiresOn()
        {
            Console.WriteLine("Testing X509_CertExpiresOn ...");
            string strCertName = null;
            string strDateTime = null;
            string strDateTime2 = null;
            string strIssuerName = null;
            string strCertOwner = null;

            strCertName = "myuser.cer";
            strCertOwner = X509.CertSubjectName(strCertName, ";");
            strDateTime = X509.CertIssuedOn(strCertName);
            strDateTime2 = X509.CertExpiresOn(strCertName);
            strIssuerName = X509.CertIssuerName(strCertName, ";");
            Console.WriteLine($"{strCertName} issued for {strCertOwner} on {strDateTime}, expired on {strDateTime2} by {strIssuerName}");
        }
        public static void V_Test_RSA_DecodeMsg()
        {
            Console.WriteLine("Testing RSA_DecodeMsg ...");
            byte[] abData = null;
            byte[] abBlock = null;
            byte[] abDigest = null;
            byte[] abDigInfo = null;
            //'Dim nDataLen As Integer
            int nBlockLen = 0;

            // 0. Create an encoded test block ready for for signing
            abData = System.Text.Encoding.Default.GetBytes("abc");
            //'nDataLen = UBound(abData) - LBound(abData) + 1
            nBlockLen = 64;
            abBlock = Rsa.EncodeMsgForSignature(nBlockLen, abData, HashAlgorithm.Sha1);
            Console.WriteLine("BLOCK   =" + Cnv.ToHex(abBlock));

            // 1. Extract the message digest =SHA1("abc")
            abDigest = Rsa.DecodeDigestForSignature(abBlock);
            if (abDigest.Length == 0)
            {
                Console.WriteLine("Decryption Error");
                return;
            }
            Console.WriteLine("Message digest is " + abDigest.Length + " bytes long");
            Console.WriteLine("HASH    =" + Cnv.ToHex(abDigest));

            // 2. Extract the full DigestInfo data
            abDigInfo = Rsa.DecodeDigestForSignature(abBlock, true);
            if (abDigInfo.Length == 0)
            {
                Console.WriteLine("Decryption Error");
                return;
            }
            Console.WriteLine("DigestInfo is " + abDigInfo.Length + " bytes long");
            Console.WriteLine("DIGINFO=" + Cnv.ToHex(abDigInfo));

        }

        public static void V_Test_CMS_MakeSigData()
        {
            Console.WriteLine("Testing CMS_MakeSigData ...");
            string strPriKeyFile = null;
            StringBuilder sbPrivateKey = null;
            //'Dim nIntKeyLen As Integer
            int nRet = 0;
            string strInputFile = null;
            string strOutputFile = null;
            string strCertFile = null;

            strPriKeyFile = "myuser.epk";
            strCertFile = "myuser.cer";
            strInputFile = "excontent.txt";
            strOutputFile = "BasicSignBy_myuser.bin";

            // First we need to read in the private key string
            // NB: This version is not encrypted
            sbPrivateKey = Rsa.ReadEncPrivateKey(strPriKeyFile, "password");
            Console.WriteLine("nIntKeyLen = " + sbPrivateKey.Length);
            if (sbPrivateKey.Length == 0)
            {
                Console.WriteLine(General.LastError());
                Console.WriteLine("Unable to retrieve private key");
                return;
            }
            Console.WriteLine("Key size=" + Rsa.KeyBits(sbPrivateKey.ToString()) + " bits");

            // Now we can sign our message
            nRet = Cms.MakeSigData(strOutputFile, strInputFile, strCertFile, sbPrivateKey.ToString(), 0);
            Console.WriteLine("CMS_MakeSigData returns " + nRet);

        }

        public static void V_Test_CMS_VerifySigData()
        {
            Console.WriteLine("Testing CMS_VerifySigData ...");
            int nRet = 0;
            string strInputFile = null;
            strInputFile = "BasicSignBy_myuser.bin";
            nRet = Cms.VerifySigData(strInputFile, "myuser.cer");
            Console.WriteLine("CMS_VerifySigData returns " + nRet + " (expecting 0)");

        }
    }
}
