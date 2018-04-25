using System;
using System.Data;
using System.Diagnostics;
using System.Reflection;
using System.IO;
using System.Text;
using CryptoSysPKI;

// CryptoSysPKI: Conversion of VB6 tests to .NET.
// [Converted to C# using SharpDevelop v3.0.0 by icsharp.net (with a few mods)]

// **************************** COPYRIGHT NOTICE ****************************
// Copyright (C) 2010-12 DI Management Services Pty Limited. 
// All rights reserved. <www.di-mgt.com.au> <www.cryptosys.net>
//   $Id: CrSysPKIExamples.cs $
//   Last updated:
//   $Date: 2012-01-14 12:27 $
//   $Version: 3.8.0 $
// ************************* END OF COPYRIGHT NOTICE ************************

static class CrSysPKIExamples
{

	// NOTE: These tests require certain files to exist in the current working directory.
	// See the function SetupTestFiles() below.

	public static void V_Test_CIPHER_Bytes()
	{
		Console.WriteLine("Testing CIPHER_Bytes ...");
		//'Dim nRet As Integer
		string strOutput = null;
		string strInput = null;
		string sCorrect = null;
		byte[] abKey = null;
		byte[] abInitV = null;
		byte[] abResult = null;
		byte[] abData = null;
		byte[] abCheck = null;
		//'Dim nDataLen As Integer

		// Set up input in byte arrays
		strInput = "Now is the time for all good men";
		sCorrect = "C3153108A8DD340C0BCB1DFE8D25D2320EE0E66BD2BB4A313FB75C5638E9E177";
		abKey = Cnv.FromHex("0123456789ABCDEFF0E1D2C3B4A59687");
		abInitV = Cnv.FromHex("FEDCBA9876543210FEDCBA9876543210");
		abData = System.Text.Encoding.Default.GetBytes(strInput);
		//'nDataLen = UBound(abData) - LBound(abData) + 1

		// Pre-dimension output array
		//'ReDim abResult(nDataLen - 1)

		Console.WriteLine("KY=" + Cnv.ToHex(abKey));
		Console.WriteLine("IV=" + Cnv.ToHex(abInitV));
		Console.WriteLine("PT=" + strInput);
		Console.WriteLine("PT=" + Cnv.ToHex(abData));
		// Encrypt in one-off process (abResult <-- abData)
		abResult = Cipher.Encrypt(abData, abKey, abInitV, CipherAlgorithm.Tdea, Mode.CBC);
		//'Console.WriteLine("CIPHER_Bytes(ENCRYPT) returns " & nRet)
		Console.WriteLine("CT=" + Cnv.ToHex(abResult));
		Console.WriteLine("OK=" + sCorrect);

		// Now decrypt back (abCheck <-- abResult)
		//'ReDim abCheck(nDataLen - 1)
		abCheck = Cipher.Decrypt(abResult, abKey, abInitV, CipherAlgorithm.Tdea, Mode.CBC);
		//'Console.WriteLine("CIPHER_Bytes(DECRYPT) returns " & nRet)
		// And decode back from a byte array into a string
		Console.WriteLine("P'=" + Cnv.ToHex(abCheck));
		strOutput = System.Text.Encoding.Default.GetString(abCheck);
		Console.WriteLine("P'=" + strOutput);

	}


	public static void V_Test_CIPHER_File()
	{
		Console.WriteLine("Testing CIPHER_File ...");
		const string MY_PATH = "";
		byte[] abKey = null;
		byte[] abIV = null;
		string strFileEnc = null;
		string strFileIn = null;
		string strFileChk = null;
		int nRet = 0;

		// Construct full path names to files
		strFileIn = MY_PATH + "hello.txt";
		strFileEnc = MY_PATH + "hello.aes128.enc.dat";
		strFileChk = MY_PATH + "hello.aes128.chk.txt";

		// Create the key as an array of bytes
		// This creates an array of 16 bytes {&HFE, &HDC, ... &H10}
		abKey = Cnv.FromHex("fedcba9876543210fedcba9876543210");
		// Create the IV at random
		//'ReDim abIV(PKI_BLK_AES_BYTES - 1)
		abIV = Rng.Bytes(Tdea.BlockSize);
		// Display the IV (this needs to be communicated separately to the recipient)
		Console.WriteLine("IV=" + Cnv.ToHex(abIV));

		// Encrypt plaintext file to ciphertext using AES-128 in counter (CTR) mode
		// (This will create a file of exactly the same size as the input)
		nRet = Cipher.FileEncrypt(strFileEnc, strFileIn, abKey, abIV, CipherAlgorithm.Aes128, Mode.CTR);
		Console.WriteLine("CIPHER_File(ENCRYPT) returns " + nRet);

		// Now decrypt it
		nRet = Cipher.FileDecrypt(strFileChk, strFileEnc, abKey, abIV, CipherAlgorithm.Aes128, Mode.CTR);
		Console.WriteLine("CIPHER_File(DECRYPT) returns " + nRet);

	}

	public static void V_Test_CIPHER_Hex()
	{
		Console.WriteLine("Testing CIPHER_Hex ...");
		int nRet = 0;
		string sPlain = null;
		string sCipher = null;
		string sCheck = null;
		string sKey = null;
		string sInitV = null;
		string sCorrect = null;

		sPlain = "5468697320736F6D652073616D706520636F6E74656E742E0808080808080808";
		//         T h i s _ s o m e _ s a m p e _ c o n t e n t .(+padding 8 x 08)
		sKey = "737C791F25EAD0E04629254352F7DC6291E5CB26917ADA32";
		sInitV = "B36B6BFB6231084E";
		sCorrect = "d76fd1178fbd02f84231f5c1d2a2f74a4159482964f675248254223daf9af8e4";

		Console.WriteLine("KY=" + sKey);
		Console.WriteLine("PT=" + sPlain);
		// Encrypt 
		sCipher = Cipher.Encrypt(sPlain, sKey, sInitV, CipherAlgorithm.Tdea, Mode.CBC);
		Console.WriteLine("CT=" + sCipher + " " + nRet);
		Console.WriteLine("OK=" + sCorrect);

		// Decrypt 
		sCheck = Cipher.Decrypt(sCipher, sKey, sInitV, CipherAlgorithm.Tdea, Mode.CBC);
		Console.WriteLine("P'=" + sCheck + " " + nRet);

	}

	public static void V_Test_CIPHER_KeyWrap()
	{
		Console.WriteLine("Testing CIPHER_KeyWrap ...");
		byte[] abWK = null;
		byte[] abKeyData = null;
		byte[] abKek = null;
		//'Dim nWkLen As Integer
		//'Dim nKdLen As Integer
		//'Dim nKekLen As Integer

		abKeyData = Cnv.FromHex("00112233 44556677 8899aabb ccddeeff");
		abKek = Cnv.FromHex("c17a44e8 e28d7d64 81d1ddd5 0a3b8914");
		//'nKdLen = UBound(abKeyData) + 1
		//'nKekLen = UBound(abKek) + 1

		abWK = Cipher.KeyWrap(abKeyData, abKek, CipherAlgorithm.Aes128);
		if (abWK.Length == 0) {
			Console.WriteLine("Cipher.KeyWrap: " + General.LastError());
			return;
		}
		Console.WriteLine("WK=" + Cnv.ToHex(abWK));

		abKeyData = Cnv.FromHex("8cbedec4 8d063e1b a46be8e3 69a9c398 d8e30ee5 42bc347c 4f30e928 ddd7db49");
		abKek = Cnv.FromHex("9e84ee99 e6a84b50 c76cd414 a2d2ec05 8af41bfe 4bf3715b f894c8da 1cd445f6");
		//'nKdLen = UBound(abKeyData) + 1
		//'nKekLen = UBound(abKek) + 1

		abWK = Cipher.KeyWrap(abKeyData, abKek, CipherAlgorithm.Aes256);
		if (abWK.Length == 0) {
			Console.WriteLine("Cipher.KeyWrap: " + General.LastError());
			return;
		}
		Console.WriteLine("WK=" + Cnv.ToHex(abWK));

		abKeyData = Cnv.FromHex("84e7f2d8 78f89fcc cd2d5eba fc56daf7 3300f27e f771cd68");
		abKek = Cnv.FromHex("8ad8274e 56f46773 8edd83d4 394e5e29 af7c4089 e4f8d9f4");
		//'nKdLen = UBound(abKeyData) + 1
		//'nKekLen = UBound(abKek) + 1

		abWK = Cipher.KeyWrap(abKeyData, abKek, CipherAlgorithm.Tdea);
		if (abWK.Length == 0) {
			Console.WriteLine("Cipher.KeyWrap: " + General.LastError());
			return;
		}
		Console.WriteLine("WK=" + Cnv.ToHex(abWK));

	}

	public static void V_Test_CIPHER_KeyUnwrap()
	{
		Console.WriteLine("Testing CIPHER_KeyUnwrap ...");
		byte[] abWK = null;
		byte[] abKeyData = null;
		byte[] abKek = null;
		//'Dim nWkLen As Integer
		//'Dim nKdLen As Integer
		//'Dim nKekLen As Integer

		abWK = Cnv.FromHex("503D75C73630A7B02ECF51B9B29B907749310B77B0B2E054");
		abKek = Cnv.FromHex("c17a44e8 e28d7d64 81d1ddd5 0a3b8914");
		//'nWkLen = UBound(abWK) + 1
		//'nKekLen = UBound(abKek) + 1

		abKeyData = Cipher.KeyUnwrap(abWK, abKek, CipherAlgorithm.Aes128);
		if (abKeyData.Length == 0) {
			Console.WriteLine("Cipher.KeyUnwrap: " + General.LastError());
			return;
		}
		Console.WriteLine("K=" + Cnv.ToHex(abKeyData));

	}

	public static void V_Test_CMS_GetSigDataDigest()
	{
		Console.WriteLine("Testing CMS_GetSigDataDigest ...");
		//'Dim nDigAlg As Integer
		string strCmsFile = null;
		string strHexDigest = null;
		strCmsFile = "DetSignByAlice.bin";
		//'strHexDigest = String(PKI_MAX_HASH_CHARS, " ")
		strHexDigest = Cms.GetSigDataDigest(strCmsFile, "", false);
		//'Console.WriteLine("CMS_GetSigDataDigest returns " & nDigAlg)
		if (strHexDigest.Length == 0) {
			return;
		}
		Console.WriteLine("Extracted digest is");
		Console.WriteLine("[" + strHexDigest + "]");

	}

	public static void V_Test_CMS_GetSigDataDigest_2()
	{
		Console.WriteLine("Testing CMS_GetSigDataDigest ...");
		string strCmsFile = null;
		string strHexDigest = null;
		//'Dim nDigAlg As Integer
		string strData = null;
		//'Dim nDataLen As Integer
		string strContentDigest = null;
		//'Dim nHashLen As Integer
		string strDigestAlg = null;

		strCmsFile = "4.2.bin";

		// 1. Get the digest value
		//'strHexDigest = String(PKI_MAX_HASH_CHARS, " ")
		strHexDigest = Cms.GetSigDataDigest(strCmsFile, "", false);
		//'Console.WriteLine("CMS_GetSigDataDigest returns " & nDigAlg)
		if (strHexDigest.Length == 0) {
			return;
		}
		Console.WriteLine("Extracted digest is");
		Console.WriteLine("[" + strHexDigest + "]");

		// 2. Go get the content - in this case it's in the signed-data object
		strData = Cms.ReadSigDataToString(strCmsFile, false);
		if (strData.Length == 0) {
			return;
		}
		Console.WriteLine("Data is [" + strData + "]");

		// 3. Compute independently the hash of what we found
		// [.NET] We have to query the signed data to find the hash algorithm
		strDigestAlg = Cms.QuerySigData(strCmsFile, "digestAlgorithm", false);
		Console.WriteLine("digestAlgorithm=" + strDigestAlg);
		strContentDigest = Hash.HexFromString(strData, HashAlgorithm.Sha1);
		Console.WriteLine("Computed hash of content is");
		Console.WriteLine("[" + strContentDigest + "]");

		// 4. Can we match this hash digest with
		//    what we extracted from the signed-data?
		if (strContentDigest == strHexDigest) {
			Console.WriteLine("SUCCESS - digests match!");
		}
		else {
			Console.WriteLine("FAILS! - no match");
		}

	}

	public static void V_Test_CMS_MakeDetachedSig()
	{
		Console.WriteLine("Testing CMS_MakeDetachedSig ...");
		int nRet = 0;
		string strEPKFile = null;
		string strCertFile = null;
		string strOutFile = null;
		string strHexDigest = null;
		string strPrivateKey = null;

		strEPKFile = "AlicePrivRSASign.epk";
		strCertFile = "AliceRSASignByCarl.cer";
		strOutFile = "DetSignByAlice.bin";
		strHexDigest = "406aec085279ba6e16022d9e0629c0229687dd48";

		// First, Alice reads her private key into a string
		strPrivateKey = Rsa.ReadEncPrivateKey(strEPKFile, "password").ToString();
		if (strPrivateKey.Length == 0) {
			Console.WriteLine("Cannot read private key");
			return;
		}

		// Alice makes a detached signature using
		// the hash of the content and her private key
		nRet = Cms.MakeDetachedSig(strOutFile, strHexDigest, strCertFile, strPrivateKey, 0);
		Console.WriteLine("CMS_MakeDetachedSig returns " + nRet);

	}

	public static void V_Test_CMS_MakeEnvData()
	{
		Console.WriteLine("Testing CMS_MakeEnvData ...");
		int nRet = 0;
		string strOutputFile = null;
		string strInputFile = null;
		string strCertFile = null;

		strOutputFile = "cmsalice2bob.p7m";
		strInputFile = "excontent.txt";
		strCertFile = "BobRSASignByCarl.cer";
		// This should return 1 (indicating one successful recipient)
		nRet = Cms.MakeEnvData(strOutputFile, strInputFile, strCertFile, 0);
		Console.WriteLine("CMS_MakeEnvData returns " + nRet);

	}

	public static void V_Test_CMS_MakeEnvData_2()
	{
		Console.WriteLine("Testing CMS_MakeEnvData ...");
		int nRet = 0;
		// This should return 2 (indicating two successful recipients)
		nRet = Cms.MakeEnvData("cms2bobandcarl.p7m", "excontent.txt", "BobRSASignByCarl.cer;CarlRSASelf.cer", 0);
		Console.WriteLine("CMS_MakeEnvData returns " + nRet);

	}

	public static void V_Test_CMS_MakeEnvData_3()
	{
		Console.WriteLine("Testing CMS_MakeEnvData ...");
		int nRet = 0;
		nRet = Cms.MakeEnvData("cms2bob_aes128.p7m", "excontent.txt", "BobRSASignByCarl.cer", CipherAlgorithm.Aes128, Cms.KeyEncrAlgorithm.Rsa_Pkcs1v1_5, 0, 0);
		Console.WriteLine("CMS_MakeEnvData returns " + nRet);

	}

	public static void V_Test_CMS_MakeEnvDataFromString()
	{
		Console.WriteLine("Testing CMS_MakeEnvDataFromString ...");
		int nRet = 0;
		// This should return 1 (indicating one successful recipient)
		nRet = Cms.MakeEnvDataFromString("cmsalice2bob1.p7m", "This is some sample content.", "BobRSASignByCarl.cer", 0);
		Console.WriteLine("CMS_MakeEnvDataFromString returns " + nRet);

	}

	public static void V_Test_CMS_MakeSigData()
	{
		Console.WriteLine("Testing CMS_MakeSigData ...");
		string strPriFile = null;
		StringBuilder sbPrivateKey = null;
		//'Dim nIntKeyLen As Integer
		int nRet = 0;
		string strInputFile = null;
		string strOutputFile = null;
		string strCertFile = null;

		strPriFile = "AlicePrivRSASign.pri";
		strCertFile = "AliceRSASignByCarl.cer";
		strInputFile = "excontent.txt";
		strOutputFile = "BasicSignByAlice.bin";

		// First we need to read in the private key string
		// NB: This version is not encrypted
		sbPrivateKey = Rsa.ReadPrivateKeyInfo(strPriFile);
		Console.WriteLine("nIntKeyLen = " + sbPrivateKey.Length);
		if (sbPrivateKey.Length == 0) {
			Console.WriteLine(General.LastError());
			Console.WriteLine("Unable to retrieve private key");
			return;
		}
		Console.WriteLine("Key size=" + Rsa.KeyBits(sbPrivateKey.ToString()) + " bits");

		// Now we can sign our message
		nRet = Cms.MakeSigData(strOutputFile, strInputFile, strCertFile, sbPrivateKey.ToString(), 0);
		Console.WriteLine("CMS_MakeSigData returns " + nRet);

	}

	public static void V_Test_CMS_MakeSigData_2()
	{
		Console.WriteLine("Testing CMS_MakeSigData ...");
		int nRet = 0;
		string strOutputFile = null;
		string strCertList = null;

		// Make a list of certs separated by semi-colons (,)
		strCertList = "CarlRSASelf.cer;" + "AliceRSASignByCarl.cer";
		Console.WriteLine("CertList=" + strCertList);
		strOutputFile = "SigDataCertsOnly.p7c";

		// Create a certs-only .p7c chain
		nRet = Cms.MakeSigData(strOutputFile, "", strCertList, "", Cms.Options.CertsOnly);
		Console.WriteLine("CMS_MakeSigData returns " + nRet);
		if (nRet != 0) Console.WriteLine(General.LastError()); 

	}

	public static void V_Test_CMS_MakeSigDataFromSigValue()
	{
		Console.WriteLine("Testing CMS_MakeSigDataFromSigValue ...");
		string strDataHex = null;
		string strSigHex = null;
		byte[] abData = null;
		byte[] abSigValue = null;
		//'Dim nSigLen As Integer
		//'Dim nDataLen As Integer
		string strCertFile = null;
		string strCmsFile = null;
		int nRet = 0;

		// Data to be signed in hex format:
		strDataHex = "54:68:69:73:20:69:73:20:73:6f:6d:65:20:73:61:6d" + "70:6c:65:20:63:6f:6e:74:65:6e:74:2e";
		// The signature (generated by the smart card) is:
		strSigHex = "2F:23:82:D2:F3:09:5F:B8:0C:58:EB:4E:9D:BF:89:9A" + "81:E5:75:C4:91:3D:D3:D0:D5:7B:B6:D5:FE:94:A1:8A" + "AC:E3:C4:84:F5:CD:60:4E:27:95:F6:CF:00:86:76:75" + "3F:2B:F0:E7:D4:02:67:A7:F5:C7:8D:16:04:A5:B3:B5" + "E7:D9:32:F0:24:EF:E7:20:44:D5:9F:07:C5:53:24:FA" + "CE:01:1D:0F:17:13:A7:2A:95:9D:2B:E4:03:95:14:0B" + "E9:39:0D:BA:CE:6E:9C:9E:0C:E8:98:E6:55:13:D4:68" + "6F:D0:07:D7:A2:B1:62:4C:E3:8F:AF:FD:E0:D5:5D:C7";
		strCertFile = "AliceRSASignByCarl.cer";
		strCmsFile = "BasicSignByAliceExternal.bin";

		// Convert the hex strings into byte arrays (non-hex chars are stripped)
		abData = Cnv.FromHex(strDataHex);
		abSigValue = Cnv.FromHex(strSigHex);
		// Compute lengths
		//'nDataLen = UBound(abData) - LBound(abData) + 1
		//'nSigLen = UBound(abSigValue) - LBound(abSigValue) + 1

		// Create the signed-data file
		nRet = Cms.MakeSigDataFromSigValue(strCmsFile, abSigValue, abData, strCertFile, 0);
		Console.WriteLine("CMS_MakeSigDataFromSigValue returns " + nRet);

	}

	public static void V_Test_CMS_ReadEnvData()
	{
		Console.WriteLine("Testing CMS_ReadEnvData ...");
		int nRet = 0;
		string strFileIn = null;
		string strFileOut = null;
		StringBuilder sbPrivateKey = null;

		// Bob reads his private key into a string
		sbPrivateKey = Rsa.ReadEncPrivateKey("BobPrivRSAEncrypt.epk", "password");
		if (sbPrivateKey.Length == 0) {
			Console.WriteLine("Cannot read private key");
			return;
		}

		// Decrypt the input file, send plaintext to new output file
		strFileIn = "cmsalice2bob.p7m";
		strFileOut = "fromalice.txt";
		nRet = Cms.ReadEnvDataToFile(strFileOut, strFileIn, "", sbPrivateKey.ToString(), 0);
		Console.WriteLine("CMS_ReadEnvData returns " + nRet);

		// Clean up
		Wipe.String(sbPrivateKey);

	}

	public static void V_Test_CMS_ReadEnvDataToString()
	{
		Console.WriteLine("Testing CMS_ReadEnvDataToString ...");
		StringBuilder sbPrivateKey = null;
		string strFileIn = null;
		string strDataOut = null;
		string strSize = null;

		strFileIn = "cms2bobandcarl.p7m";

		// First, Bob reads his private key into a string
		sbPrivateKey = Rsa.ReadEncPrivateKey("BobPrivRSAEncrypt.epk", "password");
		if (sbPrivateKey.Length == 0) {
			Console.WriteLine("Cannot read private key");
			return;
		}

		// Query the size of encrypted content (no need for an output buffer)
		strSize = Cms.QueryEnvData(strFileIn, "sizeofEncryptedContent", false);
		Console.WriteLine("CMS_QueryEnvData returns " + strSize);

		if (strSize == "0") {
			goto CleanUp;
		}

		// Pre-dimension string and read in the plaintext
		// The final plaintext will always be shorter than the encrypted content.
		strDataOut = Cms.ReadEnvDataToString(strFileIn, "", sbPrivateKey.ToString(), 0);
		Console.WriteLine("CMS_ReadEnvDataToString returns " + strDataOut.Length);
		if (strDataOut.Length > 0) {
			Console.WriteLine("Plaintext is '" + strDataOut + "'");
		}
		CleanUp:

		Wipe.String(sbPrivateKey);

	}

	public static void V_Test_CMS_ReadSigData()
	{
		Console.WriteLine("Testing CMS_ReadSigData ...");
		int nRet = 0;
		string strFileIn = null;
		string strFileOut = null;

		strFileIn = "BasicSignByAlice.bin";
		strFileOut = "BasicSignByAlice.dat";
		nRet = Cms.ReadSigDataToFile(strFileOut, strFileIn, false);
		Console.WriteLine("CMS_ReadSigData returns " + nRet);

	}

	public static void V_Test_CMS_ReadSigDataToString()
	{
		Console.WriteLine("Testing CMS_ReadSigDataToString ...");
		//'Dim nRet As Integer
		string strFileIn = null;
		string strData = null;
		//'Dim nDataLen As Integer
		strFileIn = "4.2.bin";
		strData = Cms.ReadSigDataToString(strFileIn, false);
		if (strData.Length == 0) {
			return;
		}
		Console.WriteLine("CMS_ReadSigDataToString returns " + strData.Length);
		Console.WriteLine("Data is [" + strData + "]");

	}

	public static void V_Test_CMS_VerifySigData()
	{
		Console.WriteLine("Testing CMS_VerifySigData ...");
		int nRet = 0;
		string strInputFile = null;
		strInputFile = "BasicSignByAlice.bin";
		nRet = Cms.VerifySigData(strInputFile, "", "", false);
		Console.WriteLine("CMS_VerifySigData returns " + nRet + " (expecting 0)");

	}

	public static void V_Test_CNV_ByteEncoding()
	{
		Console.WriteLine("Testing CNV_ByteEncoding ...");
		byte[] abLatin1 = null;
		byte[] abUtf8 = null;
		// Set up a byte array with the following 4 characters encoded in Latin-1
		//  U+0061 LATIN SMALL LETTER A
		//  U+00E9 LATIN SMALL LETTER E WITH ACUTE
		//  U+00F1 LATIN SMALL LETTER N WITH TILDE
		//  U+0062 LATIN SMALL LETTER B
		abLatin1 = new byte[] { (Byte)('a'), 0xe9, 0xf1, (Byte)('b') };
		// Display in hex format
		Console.WriteLine("Latin-1=" + Cnv.ToHex(abLatin1) + " (" + abLatin1.Length + " bytes)");
		// Convert encoding to UTF-8
		abUtf8 = Cnv.ByteEncoding(abLatin1, Cnv.EncodingConversion.Utf8_From_Latin1);
		// Display in hex format
		Console.WriteLine("UTF-8  =" + Cnv.ToHex(abUtf8) + " (" + abUtf8.Length + " bytes)");

	}

	public static void V_Test_CNV_UTF8BytesFromLatin1()
	{
		Console.WriteLine("Testing CNV_UTF8BytesFromLatin1 ...");
		string strData = null;
		byte[] abDataUTF8 = null;
		int nRet = 0;

		// Our original string data contains 5 non-ASCII characters
		strData = "abcóéíáñ";
		Console.WriteLine("Latin-1 string='{0}'", strData);
		Console.WriteLine(" ({0} characters)", strData.Length);
		// Convert directly to array of bytes in UTF-8 encoding
		abDataUTF8 = System.Text.Encoding.UTF8.GetBytes(strData);
		Console.WriteLine("UTF-8=(0x){0}'", Cnv.ToHex(abDataUTF8));
		Console.WriteLine(" ({0} bytes)", abDataUTF8.Length);

		// Check if this is valid UTF-8 encoding
		nRet = Cnv.CheckUTF8(abDataUTF8);
		Console.WriteLine("Cnv.CheckUTF8Bytes returns {0} (expected 2)", nRet);

		// Now put back into a string
		string strNew = System.Text.Encoding.UTF8.GetString(abDataUTF8);
		Console.WriteLine("New string='{0}' ({1} characters)", strNew, strNew.Length);

	}

	public static void V_Test_HASH_Bytes()
	{
		Console.WriteLine("Testing HASH_Bytes ...");
		//'Dim nRet As Integer
		byte[] abDigest = null;
		byte[] abMessage = null;

		// Set up message to be hashed
		abMessage = System.Text.Encoding.Default.GetBytes("abc");
		// Create default hash (SHA1)
		abDigest = Hash.BytesFromBytes(abMessage, HashAlgorithm.Sha1);
		Console.WriteLine(abMessage.Length + " " + Cnv.ToHex(abDigest));

		// Repeat for MD5
		abDigest = Hash.BytesFromBytes(abMessage, HashAlgorithm.Md5);
		Console.WriteLine(abMessage.Length + " " + Cnv.ToHex(abDigest));

	}

	public static void V_Test_HASH_File()
	{
		Console.WriteLine("Testing HASH_File ...");
		//'Dim nRet As Integer
		byte[] abDigest = null;
		string sFileName = null;

		// File to be hashed contains a total of 13 bytes: "hello world" plus CR-LF
		// 68 65 6c 6c 6f 20 77 6f 72 6c 64 0d 0a   hello world..

		sFileName = "hello.txt";

		// Create default hash (SHA1) in binary mode
		abDigest = Hash.BytesFromFile(sFileName, HashAlgorithm.Sha1);
		Console.WriteLine(abDigest.Length + " " + Cnv.ToHex(abDigest));

		// Use SHA1 in "text" mode [FUDGE]
		abDigest = Cnv.FromHex(Hash.HexFromTextFile(sFileName, HashAlgorithm.Sha1));
		Console.WriteLine(abDigest.Length + " " + Cnv.ToHex(abDigest));

		// Use MD5
		abDigest = Hash.BytesFromFile(sFileName, HashAlgorithm.Md5);
		Console.WriteLine(abDigest.Length + " " + Cnv.ToHex(abDigest));

		// Use MD5 in "text" mode
		abDigest = Cnv.FromHex(Hash.HexFromTextFile(sFileName, HashAlgorithm.Md5));
		Console.WriteLine(abDigest.Length + " " + Cnv.ToHex(abDigest));

	}

	public static void V_Test_HASH_HexFromBytes()
	{
		Console.WriteLine("Testing HASH_HexFromBytes ...");
		//'Dim nRet As Integer
		string sDigest = null;
		byte[] abMessage = null;
		// Set up message to be hashed in unambiguous Byte format
		abMessage = System.Text.Encoding.Default.GetBytes("abc");
		// Create default hash (SHA1)
		sDigest = Hash.HexFromBytes(abMessage, 0);
		Console.WriteLine(sDigest.Length + " " + sDigest);
		// Explicitly use SHA1
		sDigest = Hash.HexFromBytes(abMessage, HashAlgorithm.Sha1);
		Console.WriteLine(sDigest.Length + " " + sDigest);
		sDigest = Hash.HexFromBytes(abMessage, HashAlgorithm.Md5);
		Console.WriteLine(sDigest.Length + " " + sDigest);
		sDigest = Hash.HexFromBytes(abMessage, HashAlgorithm.Md2);
		Console.WriteLine(sDigest.Length + " " + sDigest);
		// Make output string shorter - only get back that many chars
		//'sDigest = String(16, " ")
		// [VB.NET] In .NET we can only truncate the digest string AFTER creating it
		sDigest = Hash.HexFromBytes(abMessage, HashAlgorithm.Sha1);
		sDigest = sDigest.Substring(0, 16);
		Console.WriteLine(sDigest.Length + " " + sDigest);
	}

	public static void V_Test_HASH_HexFromBytes_2()
	{
		Console.WriteLine("Testing HASH_HexFromBytes ...");
		//'Dim nRet As Integer
		string sDigest = null;
		string strMessage = null;

		strMessage = "abc";
		// Create default hash (SHA1)
		sDigest = Hash.HexFromString(strMessage, HashAlgorithm.Sha1);
		Console.WriteLine(sDigest.Length + " " + sDigest);

	}

	public static void V_Test_HASH_HexFromFile()
	{
		Console.WriteLine("Testing HASH_HexFromFile ...");
		string sDigest = null;
		string sFileName = null;

		// File to be hashed contains a total of 13 bytes: "hello world" plus CR-LF
		// 68 65 6c 6c 6f 20 77 6f 72 6c 64 0d 0a   hello world..

		sFileName = "hello.txt";

		// Create default hash (SHA1) in binary mode
		sDigest = Hash.HexFromFile(sFileName, HashAlgorithm.Sha1);
		Console.WriteLine(sDigest.Length + " " + sDigest);
		// Use SHA1 in "text" mode
		sDigest = Hash.HexFromTextFile(sFileName, HashAlgorithm.Sha1);
		Console.WriteLine(sDigest.Length + " " + sDigest);
		// Use MD5
		sDigest = Hash.HexFromFile(sFileName, HashAlgorithm.Md5);
		Console.WriteLine(sDigest.Length + " " + sDigest);
		// Use MD5 in "text" mode
		sDigest = Hash.HexFromTextFile(sFileName, HashAlgorithm.Md5);
		Console.WriteLine(sDigest.Length + " " + sDigest);

	}

	public static void V_Test_HASH_HexFromHex()
	{
		Console.WriteLine("Testing HASH_HexFromHex ...");
		string strDigest = null;
		string strData = null;
		// Compute SHA-1("abc")
		strData = "616263";
		strDigest = Hash.HexFromHex(strData, HashAlgorithm.Sha1);
		Console.WriteLine(strDigest);
		// Compute SHA-224("abc")
		strData = "616263";
		strDigest = Hash.HexFromHex(strData, HashAlgorithm.Sha224);
		Console.WriteLine(strDigest);

	}

	public static void V_Test_HMAC_Bytes()
	{
		Console.WriteLine("Testing HMAC_Bytes ...");
		byte[] abData = null;
		byte[] abKey = null;
		int nDataLen = 0;
		int nKeyLen = 0;
		byte[] abDigest = null;
		int i = 0;

		// Test case 4 from RFC 2202 and RFC 4231
		// key =           0x0102030405060708090a0b0c0d0e0f10111213141516171819
		// key_len         25
		// data =          0xcd repeated 50 times
		// data_len =      50

		nKeyLen = 25;
		abKey = new byte[nKeyLen];
		for (i = 0; i <= nKeyLen - 1; i++) {
			abKey[i] = (byte)(i + 1);
		}
		Console.WriteLine("Key=" + Cnv.ToHex(abKey));
		nDataLen = 50;
		abData = new byte[nDataLen];
		for (i = 0; i <= nDataLen - 1; i++) {
			abData[i] = 0xcd;
		}

		// Compute default HMAC (HMAC-SHA-1)
		abDigest = Hmac.BytesFromBytes(abData, abKey, HashAlgorithm.Sha1);
		if (abDigest.Length == 0) return;
 
		// ERROR
		Console.WriteLine("HMAC-SHA-1  =" + Cnv.ToHex(abDigest));
		Console.WriteLine("CORRECT     =" + "4c9007f4026250c6bc8414f9bf50c86c2d7235da");

		// Compute HMAC-MD5
		abDigest = Hmac.BytesFromBytes(abData, abKey, HashAlgorithm.Md5);
		if (abDigest.Length == 0) return;
 
		// ERROR
		Console.WriteLine("HMAC-MD5    =" + Cnv.ToHex(abDigest));
		Console.WriteLine("CORRECT     =" + "697eaf0aca3a3aea3a75164746ffaa79");

		// Compute HMAC-SHA-256
		abDigest = Hmac.BytesFromBytes(abData, abKey, HashAlgorithm.Sha256);
		if (abDigest.Length == 0) return;
 
		// ERROR
		Console.WriteLine("HMAC-SHA-256=" + Cnv.ToHex(abDigest));
		Console.WriteLine("CORRECT     =" + "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b");

	}

	public static void V_Test_HMAC_HexFromBytes()
	{
		Console.WriteLine("Testing HMAC_HexFromBytes ...");
		string strData = null;
		string strKey = null;
		byte[] abData = null;
		byte[] abKey = null;
		//'Dim nDataLen As Integer
		//'Dim nKeyLen As Integer
		string strDigest = null;

		// Test case 2 from RFC 2202 and RFC 4231
		strData = "what do ya want for nothing?";
		strKey = "Jefe";

		// Convert message and key into Byte format
		abData = System.Text.Encoding.Default.GetBytes(strData);
		abKey = System.Text.Encoding.Default.GetBytes(strKey);
		//'nDataLen = UBound(abData) - LBound(abData) + 1
		//'nKeyLen = UBound(abKey) - LBound(abKey) + 1

		// Compute default HMAC (HMAC-SHA-1)
		strDigest = Hmac.HexFromBytes(abData, abKey, HashAlgorithm.Sha1);
		if (strDigest.Length == 0) return;
 
		// ERROR
		Console.WriteLine("HMAC-SHA-1  =" + strDigest);
		Console.WriteLine("CORRECT     =" + "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");

		// Compute HMAC-MD5
		strDigest = Hmac.HexFromBytes(abData, abKey, HashAlgorithm.Md5);
		if (strDigest.Length == 0) return;
 
		// ERROR
		Console.WriteLine("HMAC-MD5    =" + strDigest);
		Console.WriteLine("CORRECT     =" + "750c783e6ab0b503eaa86e310a5db738");

		// Compute HMAC-SHA-256
		strDigest = Hmac.HexFromBytes(abData, abKey, HashAlgorithm.Sha256);
		if (strDigest.Length == 0) return;
 
		// ERROR
		Console.WriteLine("HMAC-SHA-256=" + strDigest);
		Console.WriteLine("CORRECT     =" + "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");

		// Compute HMAC-SHA-512
		strDigest = Hmac.HexFromBytes(abData, abKey, HashAlgorithm.Sha512);
		if (strDigest.Length == 0) return;
 
		// ERROR
		Console.WriteLine("HMAC-SHA-512=" + strDigest);
		Console.WriteLine("CORRECT     =" + "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554" + "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737");

	}

	public static void V_Test_HMAC_HexFromHex()
	{
		Console.WriteLine("Testing HMAC_HexFromHex ...");
		string strDigest = null;
		string strData = null;
		string strKey = null;
		// Ref: RFC 2202 and RFC 4231
		// Test Case 1
		// Key =  0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b
		//        0b0b0b0b                    (20 bytes)
		// Data = 4869205468657265            ("Hi There")

		// Compute HMAC-SHA-1
		strData = "4869205468657265";
		strKey = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
		strDigest = Hmac.HexFromHex(strData, strKey, HashAlgorithm.Sha1);
		Console.WriteLine(strDigest);
		// Compute HMAC-SHA-256
		strDigest = Hmac.HexFromHex(strData, strKey, HashAlgorithm.Sha256);
		Console.WriteLine(strDigest);

	}

	public static void V_Test_OCSP_MakeRequest()
	{
		Console.WriteLine("Testing OCSP_MakeRequest ...");
		//'Dim nChars As Integer
		string strCertFile = null;
		string strIssuerFile = null;
		string strBuf = null;

		strIssuerFile = "UTNUSERFirst-Object.cer";
		strCertFile = "dims.cer";

		Console.WriteLine("IssuerFile=" + strIssuerFile);
		Console.WriteLine("CertFile=" + strCertFile);
		// Find required length (or error)
		strBuf = Ocsp.MakeRequest(strIssuerFile, strCertFile, HashAlgorithm.Sha1);
		Console.WriteLine("OCSP_MakeRequest returns " + strBuf.Length + "(expected +ve)");
		Console.WriteLine("OCSPRequest=" + strBuf);

		// Pass a hex serial number instead of filename
		strCertFile = "#x 00 FB C7 23 22 8C 8C 80 22 D8 85 92 23 DE E7 06 60";
		Console.WriteLine("Cert SerialNumber=" + strCertFile);
		strBuf = Ocsp.MakeRequest(strIssuerFile, strCertFile, HashAlgorithm.Sha1);
		Console.WriteLine("OCSP_MakeRequest returns " + strBuf.Length + "(expected +ve)");
		Console.WriteLine("OCSPRequest=" + strBuf);

	}

	public static void V_Test_OCSP_ReadResponse()
	{
		Console.WriteLine("Testing OCSP_ReadResponse ...");
		//'Dim nChars As Integer
		string strResponseFile = null;
		string strIssuerFile = null;
		string strBuf = null;
		strResponseFile = "ocsp_response_ok_dims.dat";
		strIssuerFile = "UTNUSERFirst-Object.cer";
		Console.WriteLine("ResponseFile=" + strResponseFile);
		Console.WriteLine("IssuerFile=" + strIssuerFile);
		strBuf = Ocsp.ReadResponse(strResponseFile, strIssuerFile);
		Console.WriteLine("OCSP_ReadResponse returns " + strBuf.Length + " (expected +ve)");
		Console.WriteLine("OCSPResponse=" + strBuf);

	}

	public static void V_Test_PEM_FileFromBinFile()
	{
		Console.WriteLine("Testing PEM_FileFromBinFile ...");
		int nRet = 0;
		string strBinFile = null;
		string strPEMFile = null;
		string strDigest = null;

		// Input file is a DER-encoded X.509 certificate
		// (at 227 bytes, the smallest we could devise)
		strBinFile = "smallca.cer";
		strPEMFile = "smallca.pem.cer";

		// Convert to a PEM file
		nRet = Pem.FileFromBinFile(strPEMFile, strBinFile, "CERTIFICATE", 72);
		Console.WriteLine("PEM_FileFromBinFile returns " + nRet + " (expecting 0)");

		// To prove we did it properly, compute the thumbprint of the two certs
		strDigest = X509.CertThumb(strBinFile, HashAlgorithm.Sha1);
		if (strDigest.Length > 0) {
			Console.WriteLine("SHA-1(der-file)=" + strDigest);
		}
		else {
			Console.WriteLine("ERROR: computing cert thumb");
		}
		strDigest = X509.CertThumb(strPEMFile, HashAlgorithm.Sha1);
		if (strDigest.Length > 0) {
			Console.WriteLine("SHA-1(pem-file)=" + strDigest);
		}
		else {
			Console.WriteLine("ERROR: computing cert thumb");
		}

	}

	public static void V_Test_PEM_FileToBinFile()
	{
		Console.WriteLine("Testing PEM_FileToBinFile ...");
		int nRet = 0;
		string strBinFile = null;
		string strPEMFile = null;

		// Input file is a PEM-encoded X.509 certificate
		strPEMFile = "smallca.pem.cer";
		strBinFile = "smallca-copy.cer";

		// Convert to a binary file
		nRet = Pem.FileToBinFile(strBinFile, strPEMFile);
		Console.WriteLine("PEM_FiletoBinFile returns " + nRet + " (expecting 0)");

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

		strOutputFile = "Bob1.pfx";
		strCertFile = "BobRSASignByCarl.cer";
		strKeyFile = "BobPrivRSAEncrypt.epk";
		sbPassword = new StringBuilder("password");

		// Given Bob's certificate and encrypted private key file (with password "password"),
		// create a PKCS-12 (pfx/p12) file.
		nRet = Pfx.MakeFile(strOutputFile, strCertFile, strKeyFile, sbPassword.ToString(), "Bob's ID", Pfx.Options.Default);
		Console.WriteLine("Pfx.MakeFile returns " + nRet);

		// Now verify that the signature is OK
		isOK = Pfx.SignatureIsValid(strOutputFile, sbPassword.ToString());
		Console.WriteLine("Pfx.SignatureIsValid returns " + isOK);

		// Clean up
		Wipe.String(sbPassword);

	}

	public static void V_Test_PFX_MakeFile_2()
	{
		Console.WriteLine("Testing PFX_MakeFile ...");
		string strOutputFile = null;
		string strCertFile = null;
		int nRet = 0;

		strOutputFile = "CarlNoKey.p12";
		strCertFile = "CarlRSASelf.cer";

		// Given Carl's certificate only,
		// create a PKCS-12 (pfx/p12) file with no private key.
		nRet = Pfx.MakeFile(strOutputFile, strCertFile, "", "", "Carl's ID", 0);
		Console.WriteLine("PFX_MakeFile returns " + nRet);

	}

	public static void V_Test_PKI_CompileTime()
	{
		Console.WriteLine("Testing PKI_CompileTime ...");
		string strCompiledOn = null;

		strCompiledOn = General.CompileTime();
		Console.WriteLine("General.CompileTime " + " [" + strCompiledOn + "]");

	}

	public static void V_Test_PKI_ErrorLookup()
	{
		Console.WriteLine("Testing PKI_ErrorLookup ...");
		int nErrCode = 0;
		string strErrMsg = null;

		nErrCode = 25;
		strErrMsg = General.ErrorLookup(nErrCode);
		Console.WriteLine("ErrorLookup(" + nErrCode + ")=" + strErrMsg);

	}

	public static void V_Test_PKI_LicenceType()
	{
		Console.WriteLine("Testing PKI_LicenceType ...");
		char chr = '\0';
		chr = General.LicenceType();
		Console.WriteLine("PKI_LicenceType is " + chr);

	}

	public static void V_Test_PKI_ModuleName()
	{
		Console.WriteLine("Testing PKI_ModuleName ...");
		string strModuleName = null;

		strModuleName = General.ModuleName();
		Console.WriteLine("General.ModuleName returns " + " [" + strModuleName + "]");

	}

	public static void V_Test_PKI_PowerUpTests()
	{
		Console.WriteLine("Testing PKI_PowerUpTests ...");
		int nRet = 0;

		nRet = General.PowerUpTests();
		Console.WriteLine("General.PowerUpTests returns " + nRet);

	}

	public static void V_Test_PKI_Version()
	{
		Console.WriteLine("Testing PKI_Version ...");
		int nRet = 0;

		nRet = General.Version();
		Console.WriteLine("General.Version returns " + nRet);

	}

	public static void V_Test_PWD_PromptEx()
	{
		Console.WriteLine("Testing PWD_PromptEx ...");
		string strPassword = null;

		strPassword = Pwd.Prompt(512, "Demo of PWD_PromptEx", "Type secret phrase:");
		// Do something with the password...
		if (strPassword.Length > 0) {
			Console.WriteLine("Password entered=" + strPassword);
		}
		//'ElseIf nLen < 0 Then
		//'Console.WriteLine("User cancelled")
		else {
			Console.WriteLine("Empty password entered or User Cancelled");
		}
		// Clean up
		//'Call WIPE_String(strPassword, nLen)
		strPassword = "";

	}

	public static void V_Test_RNG_Bytes()
	{
		Console.WriteLine("Testing RNG_Bytes ...");
		byte[] abData = null;
		int nDataLen = 0;

		nDataLen = 16;
		abData = Rng.Bytes(nDataLen);
		Console.WriteLine(Cnv.ToHex(abData));

	}

	public static void V_Test_RNG_BytesWithPrompt()
	{
		Console.WriteLine("Testing RNG_BytesWithPrompt ...");
		byte[] abData = null;
		int nDataLen = 0;

		// Allocate byte array for 16 bytes
		nDataLen = 16;

		// Default prompt with default 112-bit security strength
		abData = Rng.BytesWithPrompt(nDataLen);
		Console.WriteLine(Cnv.ToHex(abData));

		// User-selected prompt with 128-bit security strength
		abData = Rng.BytesWithPrompt(nDataLen, "Our own prompt: type until done...", Rng.Strength.Bits_128);
		Console.WriteLine(Cnv.ToHex(abData));

	}

	public static void V_Test_RNG_Initialize()
	{
		Console.WriteLine("Testing RNG_Initialize ...");
		string strSeedFile = null;
		bool isOK = false;
		byte[] abData = null;
		int nDataLen = 0;
		int i = 0;

		strSeedFile = "seed.dat";
		// 1. Initialize
		isOK = Rng.Initialize(strSeedFile);
		Console.WriteLine("RNG_Initialize('" + strSeedFile + "') returns " + isOK + " (expecting True)");

		// 2. Generate some random data
		nDataLen = 24;
		for (i = 1; i <= 3; i++) {
			abData = Rng.Bytes(nDataLen);
			Console.WriteLine(Cnv.ToHex(abData));
		}

		// 3. Update the seed file
		isOK = Rng.UpdateSeedFile(strSeedFile);
		Console.WriteLine("RNG_UpdateSeedFile('" + strSeedFile + "') returns " + isOK + " (expecting True)");

	}

	public static void V_Test_RNG_Number()
	{
		Console.WriteLine("Testing RNG_Number ...");
		int i = 0;
		for (i = 1; i <= 10; i++) {
			Console.WriteLine(Rng.Number(-1000000, 1000000));
		}

	}

	public static void V_Test_RNG_Test()
	{
		Console.WriteLine("Testing RNG_Test ...");
		string strFileName = null;
		bool isOK = false;

		strFileName = "pkiFips140.txt";
		isOK = Rng.Test(strFileName);
		Console.WriteLine("Rng.Test('" + strFileName + "') returns " + isOK + " (expecting True)");

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
		if (abDigest.Length == 0) {
			Console.WriteLine("Decryption Error");
			return;
		}
		Console.WriteLine("Message digest is " + abDigest.Length + " bytes long");
		Console.WriteLine("HASH    =" + Cnv.ToHex(abDigest));

		// 2. Extract the full DigestInfo data
		abDigInfo = Rsa.DecodeDigestForSignature(abBlock, true);
		if (abDigInfo.Length == 0) {
			Console.WriteLine("Decryption Error");
			return;
		}
		Console.WriteLine("DigestInfo is " + abDigInfo.Length + " bytes long");
		Console.WriteLine("DIGINFO=" + Cnv.ToHex(abDigInfo));

	}

	public static void V_Test_RSA_EncodeMsg()
	{
		Console.WriteLine("Testing RSA_EncodeMsg ...");
		byte[] abData = new byte[4];
		byte[] abBlock = null;
		byte[] abCheck = null;
		//int nDataLen = 0;
		int nBlockLen = 0;

		// Our message data, 4 bytes long
		abData[0] = 0xde;
		abData[1] = 0xad;
		abData[2] = 0xbe;
		abData[3] = 0xef;
		//nDataLen = 4;
		Console.WriteLine("DATA   =" + Cnv.ToHex(abData));
		// Set up output block with correct size
		nBlockLen = 64;
		// Encode ready for encryption with default algorithm
		abBlock = Rsa.EncodeMsgForEncryption(nBlockLen, abData, Rsa.EME.PKCSv1_5);
		if ((abBlock.Length == 0)) {
			Console.WriteLine("Encoding Error");
			return;
		}
		Console.WriteLine("BLOCK  =" + Cnv.ToHex(abBlock));

		// Now encrypt this block using RSA_RawPublic
		// ...
		// ... and send to recipient ...
		// ...
		// who decrypts using RSA_RawPrivate to get the encoded block

		// Recover the message from the encoded block
		// How long is it?
		abCheck = Rsa.DecodeMsgForEncryption(abBlock, Rsa.EME.PKCSv1_5);
		if ((abCheck.Length == 0)) {
			Console.WriteLine("Decryption Error");
			return;
		}
		Console.WriteLine("DECODED=" + Cnv.ToHex(abCheck));

		// Alternative using more-secure OAEP algorithm
		abBlock = Rsa.EncodeMsgForEncryption(nBlockLen, abData, Rsa.EME.OAEP);
		if ((abBlock.Length == 0)) {
			Console.WriteLine("Encoding Error");
			return;
		}
		Console.WriteLine("BLOCK  =" + Cnv.ToHex(abBlock));
		// ...
		abCheck = Rsa.DecodeMsgForEncryption(abBlock, Rsa.EME.OAEP);
		if ((abCheck.Length == 0)) {
			Console.WriteLine("Decryption Error");
			return;
		}
		Console.WriteLine("DECODED=" + Cnv.ToHex(abCheck));

	}

	public static void V_Test_RSA_FromXMLString()
	{
		Console.WriteLine("Testing RSA_FromXMLString ...");
		string strInternalKey = null;
		string strXML = null;
		int nRet = 0;

		strXML = "<RSAKeyValue>" + "<Modulus>CmZ5HcaYgWjeerd0Gbt/sMABxicQJwB1FClC4ZqNjFH" + "QU7PjeCod5dxa9OvplGgXARSh3+Z83Jqa9V1lViC7qw==</Modulus>" + "<Exponent>AQAB</Exponent>" + "</RSAKeyValue>";

		strInternalKey = Rsa.FromXMLString(strXML, false);
		if (strInternalKey.Length == 0) {
			Console.WriteLine("Error: ");
			return;
		}

		Console.WriteLine("INTKEY=" + strInternalKey);

		nRet = Rsa.CheckKey(strInternalKey);
		Console.WriteLine("RSA_CheckKey returns " + nRet);

	}

	public static void V_Test_RSA_FromXMLString_2()
	{
		Console.WriteLine("Testing RSA_FromXMLString ...");
		string strInternalKey = null;
		string strXML = null;
		int nRet = 0;

		strXML = "<RSAKeyValue>" + "<Modulus EncodingType='hexBinary'>0A66791D" + "C6988168DE7AB77419BB7FB0C001C627102700751429" + "42E19A8D8C51D053B3E3782A1DE5DC5AF4EBE9946817" + "0114A1DFE67CDC9A9AF55D655620BBAB</Modulus>" + "<Exponent EncodingType='hexBinary'>010001</Exponent>" + "</RSAKeyValue>";

		strInternalKey = Rsa.FromXMLString(strXML, false);
		if (strInternalKey.Length == 0) {
			Console.WriteLine("Error: ");
			return;
		}

		Console.WriteLine("INTKEY=" + strInternalKey);

		nRet = Rsa.CheckKey(strInternalKey);
		Console.WriteLine("RSA_CheckKey returns " + nRet);

	}

	public static void V_Test_RSA_GetPublicKeyFromCert()
	{
		Console.WriteLine("Testing RSA_GetPublicKeyFromCert ...");
		string strCertFile = null;
		string strKeyFile = null;
		StringBuilder sbPublicKey = null;
		int nRet = 0;

		strCertFile = "AliceRSASignByCarl.cer";
		sbPublicKey = Rsa.GetPublicKeyFromCert(strCertFile);
		Console.WriteLine("RSA_GetPublicKeyFromCert returns " + sbPublicKey.Length + " (expecting +ve)");
		if (sbPublicKey.Length == 0) {
			Console.WriteLine("ERROR: " + General.LastError());
			return;
		}
		Console.WriteLine("Public key is " + Rsa.KeyBits(sbPublicKey.ToString()) + " bits long");

		// Now save as a PKCS#1 public key file
		strKeyFile = "AlicePubRSA.pub";
		nRet = Rsa.SavePublicKey(strKeyFile, sbPublicKey.ToString(), 0);
		Console.WriteLine("RSA_SavePublicKey returns " + nRet);
		if (nRet == 0) {
			Console.WriteLine("Saved as public key file '" + strKeyFile + "'");
		}
		else {
			Console.WriteLine("ERROR: " + General.LastError());
		}

	}

	public static void V_Test_RSA_KeyMatch()
	{
		Console.WriteLine("Testing RSA_KeyMatch ...");
		string strCertFile = null;
		string strKeyFile = null;
		StringBuilder sbPassword = null;
		StringBuilder sbPublicKey = null;
		StringBuilder sbPrivateKey = null;
		int nRet = 0;

		// Input files
		strCertFile = "AAA010101AAAsd.cer";
		strKeyFile = "AAA010101AAA_0408021316S.key";
		// Test password - CAUTION: DO NOT hardcode production passwords!
		sbPassword = new StringBuilder("Empresa1");

		// Read in private key from encrypted .key file
		sbPrivateKey = Rsa.ReadEncPrivateKey(strKeyFile, sbPassword.ToString());
		if (sbPrivateKey.Length > 0) {
			Console.WriteLine("Private key is " + Rsa.KeyBits(sbPrivateKey.ToString()) + " bits");
		}
		else {
			Console.WriteLine("ERROR: Cannot read private key file.");
			return;
		}

		// Clean up password as we are done with it
		Wipe.String(sbPassword);

		// Read in public key from certificate
		sbPublicKey = Rsa.GetPublicKeyFromCert(strCertFile);
		if (sbPublicKey.Length > 0) {
			Console.WriteLine("Public key is " + Rsa.KeyBits(sbPublicKey.ToString()) + " bits");
		}
		else {
			Console.WriteLine("ERROR: Cannot read certificate file.");
			return;
		}

		// See if the two key strings match
		nRet = Rsa.KeyMatch(sbPrivateKey.ToString(), sbPublicKey.ToString());
		if (nRet == 0) {
			Console.WriteLine("OK, key strings match.");
		}
		else {
			Console.WriteLine("FAILED: key strings do not match.");
		}

		// Clean up private key string
		Wipe.String(sbPrivateKey);

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
		strPriKeyFile = "BobPrivRSAEncrypt.epk";
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

	public static void V_Test_RSA_ReadPrivateKeyFromPFX()
	{
		Console.WriteLine("Testing RSA_ReadPrivateKeyFromPFX ...");
		string strPfxFile = null;
		StringBuilder sbPrivateKey = null;
		StringBuilder sbPassword = null;
		int nCode = 0;
		int nRet = 0;

		strPfxFile = "bob.pfx";
		sbPassword = new StringBuilder("password");

		// Read private key from PFX file into internal string form
		sbPrivateKey = Rsa.ReadPrivateKeyFromPFX(strPfxFile, sbPassword.ToString());
		if (sbPrivateKey.Length == 0) return;
 
		// Catch error here

		// Display some info about it
		Console.WriteLine("Private key length = {0} bits", Rsa.KeyBits(sbPrivateKey.ToString()));
		nCode = Rsa.KeyHashCode(sbPrivateKey.ToString());
		Console.WriteLine("KeyHashCode={0,8:X}", nCode);
		nRet = Rsa.CheckKey(sbPrivateKey);
		Console.WriteLine("Rsa.CheckKey returns " + nRet + ": (PKI_VALID_PRIVATEKEY=" + 0 + ")");

		// Clean up
		Wipe.String(sbPrivateKey);
		Wipe.String(sbPassword);
	}

	public static void V_Test_RSA_MakeKeys()
	{
		Console.WriteLine("Testing RSA_MakeKeys ...");
		int nRet = 0;
		string sPublicKeyFile = null;
		string sPrivateKeyFile = null;
		string sPassword = null;

		sPublicKeyFile = "mykey.pub";
		sPrivateKeyFile = "mykey.epk";
		sPassword = "password";

		// Create a new pair of RSA keys saved as BER-encoded files
		Console.WriteLine("About to create a new RSA key pair...");

		nRet = Rsa.MakeKeys(sPublicKeyFile, sPrivateKeyFile, 512, Rsa.PublicExponent.Exp_EQ_3, 1000, sPassword, Rsa.PbeOptions.PbeWithMD5AndDES_CBC, false);

		Console.WriteLine("RSA_MakeKeys returns " + nRet + " (expected 0)");

	}

	public static void V_Test_RSA_RawPrivate()
	{
		Console.WriteLine("Testing RSA_RawPrivate ...");
		string strEPKFile = null;
		string strPubFile = null;
		string strPassword = null;
		StringBuilder sbPublicKey = null;
		StringBuilder sbPrivateKey = null;
		byte[] abData = null;
		string sHexData = null;

		strEPKFile = "rsa508.epk";
		strPassword = "password";

		// Read in the deciphered private key string
		sbPrivateKey = Rsa.ReadEncPrivateKey(strEPKFile, strPassword);
		if (sbPrivateKey.Length == 0) {
			Console.WriteLine("Unable to retrieve private key");
			return;
		}
		Console.WriteLine("PriKey length= " + Rsa.KeyBits(sbPrivateKey.ToString()) + " bits");

		// Create some raw data to be RSA'd
		// Ref: 3.2 Signing the CertificationRequestInfo encoding
		// 64-octet EB in full:
		//00 01 ff ff ff ff ff ff ff ff ff ff ff ff ff ff
		//ff ff ff ff ff ff ff ff ff ff ff ff ff 00 30 20
		//30 0c 06 08 2a 86 48 86 f7 0d 02 02 05 00 04 10
		//dc a9 ec f1 c1 5c 1b d2 66 af f9 c8 79 93 65 cd

		sHexData = "0001ffffffffffffffffffffffffffff" + "ffffffffffffffffffffffffff003020" + "300c06082a864886f70d020205000410" + "dca9ecf1c15c1bd266aff9c8799365cd";

		abData = Cnv.FromHex(sHexData);
		Console.WriteLine("Input:  " + Cnv.ToHex(abData));

		// Now we have our data in a byte array and
		// our private key in string format,
		// we are ready to do a "raw" operation
		abData = Rsa.RawPrivate(abData, sbPrivateKey.ToString());
		Console.WriteLine("RSA_RawPrivate returns " + abData.Length);
		if (abData.Length == 0) {
			Console.WriteLine("ERROR: " + General.LastError());
		}
		else {
			// Display our results in hex format
			Console.WriteLine("Output: " + Cnv.ToHex(abData));
		}

		// Get the corresponding Public Key, also in a file
		strPubFile = "rsa508.pub";
		sbPublicKey = Rsa.ReadPublicKey(strPubFile);
		Console.WriteLine("PubKey length= " + Rsa.KeyBits(sbPublicKey.ToString()) + " bits");

		// Do a "raw" encryption with the public key
		abData = Rsa.RawPublic(abData, sbPublicKey.ToString(), 0);
		Console.WriteLine("RSA_RawPublic returns " + abData.Length);
		if (abData.Length == 0) {
			Console.WriteLine("ERROR: " + General.LastError());
		}
		else {
			// Display our results in hex format
			Console.WriteLine("Decrypt:" + Cnv.ToHex(abData));
		}

	}

	public static void V_Test_RSA_RawPublic()
	{
		Console.WriteLine("Testing RSA_RawPublic ...");
		string sEncDataHex = null;
		byte[] abData = null;
		string strCertFile = null;
		StringBuilder sbPublicKey = null;

		// Cut and paste from DUMPASN1 output
		sEncDataHex = "2F 23 82 D2 F3 09 5F B8 0C 58 EB 4E" + "9D BF 89 9A 81 E5 75 C4 91 3D D3 D0" + "D5 7B B6 D5 FE 94 A1 8A AC E3 C4 84" + "F5 CD 60 4E 27 95 F6 CF 00 86 76 75" + "3F 2B F0 E7 D4 02 67 A7 F5 C7 8D 16" + "04 A5 B3 B5 E7 D9 32 F0 24 EF E7 20" + "44 D5 9F 07 C5 53 24 FA CE 01 1D 0F" + "17 13 A7 2A 95 9D 2B E4 03 95 14 0B" + "E9 39 0D BA CE 6E 9C 9E 0C E8 98 E6" + "55 13 D4 68 6F D0 07 D7 A2 B1 62 4C" + "E3 8F AF FD E0 D5 5D C7";

		// Convert to bytes
		abData = Cnv.FromHex(sEncDataHex);
		// Check
		Console.WriteLine(Cnv.ToHex(abData));

		strCertFile = "AliceRSASignByCarl.cer";
		// Read in PublicKey as base64 string - pre-dimension first
		sbPublicKey = Rsa.GetPublicKeyFromCert(strCertFile);
		Console.WriteLine("IntKeyLen = " + sbPublicKey.Length);
		if (sbPublicKey.Length == 0) {
			Console.WriteLine(General.LastError());
			Console.WriteLine("Unable to retrieve private key");
			return;
		}
		Console.WriteLine("PubKey length= " + Rsa.KeyBits(sbPublicKey.ToString()) + " bits");

		// Verify using the public key
		Console.WriteLine("Input:  " + Cnv.ToHex(abData));
		abData = Rsa.RawPublic(abData, sbPublicKey.ToString());
		Console.WriteLine("Output: " + Cnv.ToHex(abData));

	}

	public static void V_Test_RSA_ReadPrivateKeyInfo()
	{
		Console.WriteLine("Testing RSA_ReadPrivateKeyInfo ...");
		string strPriFile = null;
		string strEPKFile = null;
		string strPrivateKey = null;
		string strPK1 = null;
		int nRet = 0;

		// Read in Bob's unencrypted PrivateKeyInfo data
		strPriFile = "BobPrivRSAEncrypt.pri";
		strPrivateKey = Rsa.ReadPrivateKeyInfo(strPriFile).ToString();
		if (strPrivateKey.Length == 0) {
			Console.WriteLine("Failed to read Private Key file");
			return;
		}
		// Now we save it with a password
		strEPKFile = "BobPrivRSAEncrypt.epk";
		nRet = Rsa.SaveEncPrivateKey(strEPKFile, strPrivateKey, 1000, "password", 0, 0);
		Console.WriteLine("RSA_SaveEncPrivateKey returns " + nRet);

		// Check we can read it
		strPK1 = Rsa.ReadEncPrivateKey(strEPKFile, "password").ToString();

		// To compare these strings, use the RSA_KeyHashCode function
		Console.WriteLine("{0,8:X}", Rsa.KeyHashCode(strPK1));
		Console.WriteLine("{0,8:X}", Rsa.KeyHashCode(strPrivateKey));
		if (Rsa.KeyHashCode(strPK1) == Rsa.KeyHashCode(strPrivateKey)) {
			Console.WriteLine("Key string values match.");
		}
		else {
			Console.WriteLine("ERROR: key strings do not match.");
		}

	}

	public static void V_Test_RSA_SaveEncPrivateKey()
	{
		Console.WriteLine("Testing RSA_SaveEncPrivateKey ...");
		string strPriFile = null;
		string strEPKFile = null;
		string strPrivateKey = null;
		string strPK1 = null;
		int nRet = 0;

		strPriFile = "CarlPrivRSASign.pri";

		// Read in Carl's unencrypted PrivateKeyInfo data
		strPrivateKey = Rsa.ReadPrivateKeyInfo(strPriFile).ToString();
		if (strPrivateKey.Length == 0) {
			Console.WriteLine("Failed to read Private Key file");
			return;
		}
		Console.WriteLine("Private key length is " + Rsa.KeyBits(strPrivateKey) + " bits");

		// Now save it in PKCS#8 encrypted form with a password
		strEPKFile = "CarlPrivRSASign.epk";
		nRet = Rsa.SaveEncPrivateKey(strEPKFile, strPrivateKey, 1000, "password", 0, 0);
		Console.WriteLine("Rsa.SaveEncPrivateKey returns " + nRet + " (expected 0)");

		// Check we can read it 
		strPK1 = Rsa.ReadEncPrivateKey(strEPKFile, "password").ToString();
		if (strPK1.Length > 0) {
			Console.WriteLine("Encrypted private key is " + Rsa.KeyBits(strPK1) + " bits");
		}
		else {
			Console.WriteLine("Unable to read encrypted private key");
		}

		// To compare these strings, use the RSA_KeyHashCode function
		Console.WriteLine("HashCode(original prikeyinfo) ={0,8:X}", Rsa.KeyHashCode(strPrivateKey));
		Console.WriteLine("HashCode(encrypted prikeyinfo)={0,8:X}", Rsa.KeyHashCode(strPK1));
		if (Rsa.KeyHashCode(strPK1) == Rsa.KeyHashCode(strPrivateKey)) {
			Console.WriteLine("OK, Key string values match.");
		}
		else {
			Console.WriteLine("ERROR: key strings do not match.");
		}

	}

	public static void V_Test_RSA_SavePrivateKeyInfo()
	{
		Console.WriteLine("Testing RSA_SavePrivateKeyInfo ...");
		string strEPKFile = null;
		string strPriFile = null;
		string strPEMFile = null;
		string strPassword = null;
		string strPrivateKey = null;
		int nRet = 0;

		strEPKFile = "rsa508.epk";
		strPriFile = "rsa508.pri";
		strPEMFile = "rsa508.pem";
		strPassword = "password";

		// Read in the deciphered private key string
		strPrivateKey = Rsa.ReadEncPrivateKey(strEPKFile, strPassword).ToString();
		if (strPrivateKey.Length == 0) {
			Console.WriteLine("Unable to retrieve private key");
			return;
		}
		Console.WriteLine("Key size=" + Rsa.KeyBits(strPrivateKey) + " bits");

		// Save as unencrypted PrivateKeyInfo file
		nRet = Rsa.SavePrivateKeyInfo(strPriFile, strPrivateKey, Rsa.Format.Binary);
		Console.WriteLine("Rsa.SavePrivateKeyInfo returns " + nRet);

		// Save as unencrypted PEM-format file
		nRet = Rsa.SavePrivateKeyInfo(strPEMFile, strPrivateKey, Rsa.Format.PEM);
		Console.WriteLine("Rsa.SavePrivateKeyInfo returns " + nRet);

	}

	public static void V_Test_RSA_ToXMLString()
	{
		Console.WriteLine("Testing RSA_ToXMLString ...");
		string strEPKFile = null;
		string strPassword = null;
		string strPrivateKey = null;
		string strXML = null;

		strEPKFile = "AlicePrivRSASign.epk";
		strPassword = "password";

		// Read in the deciphered private key string in our internal format
		strPrivateKey = Rsa.ReadEncPrivateKey(strEPKFile, strPassword).ToString();
		if (strPrivateKey.Length == 0) {
			Console.WriteLine("Unable to retrieve private key");
			return;
		}
		Console.WriteLine("Key size=" + Rsa.KeyBits(strPrivateKey) + " bits");

		// Convert to XML
		strXML = Rsa.ToXMLString(strPrivateKey, Rsa.XmlOptions.ForceRSAKeyValue);
		Console.WriteLine("XML=" + strXML);

	}

	public static void V_Test_TDEA_B64Mode()
	{
		Console.WriteLine("Testing TDEA_B64Mode ...");
		string sHexCorrect = null;
		string sHexInput = null;
		string sHexKey = null;
		string sHexInitV = null;
		string sOutput = null;
		string sInput = null;
		string sKey = null;
		string sInitV = null;
		string sCorrect = null;

		// Start with input in hex
		sHexInput = "5468697320736F6D652073616D706520636F6E74656E742E0808080808080808";
		//            T h i s _ s o m e _ s a m p e _ c o n t e n t . (padding 8 x 08)
		sHexKey = "737C791F25EAD0E04629254352F7DC6291E5CB26917ADA32";
		sHexInitV = "B36B6BFB6231084E";
		sHexCorrect = "d76fd1178fbd02f84231f5c1d2a2f74a4159482964f675248254223daf9af8e4";

		// Convert to base64
		sInput = System.Convert.ToBase64String(Cnv.FromHex(sHexInput));
		sKey = System.Convert.ToBase64String(Cnv.FromHex(sHexKey));
		sInitV = System.Convert.ToBase64String(Cnv.FromHex(sHexInitV));
		sCorrect = System.Convert.ToBase64String(Cnv.FromHex(sHexCorrect));

		Console.WriteLine("KY=" + " " + sKey);
		Console.WriteLine("PT=" + " " + sInput);
		Console.WriteLine("IV=" + " " + sInitV);
		sOutput = Tdea.Encrypt(sInput, sKey, Mode.CBC, sInitV, EncodingBase.Base64);
		Console.WriteLine("CT=" + " " + sOutput + " " + General.ErrorCode());
		Console.WriteLine("OK=" + " " + sCorrect);

		sInput = sOutput;
		sOutput = Tdea.Decrypt(sInput, sKey, Mode.CBC, sInitV, EncodingBase.Base64);
		Console.WriteLine("P'=" + " " + sOutput + " " + General.ErrorCode());

	}

	public static void V_Test_TDEA_BytesMode()
	{
		Console.WriteLine("Testing TDEA_BytesMode ...");
		string sOutput = null;
		string sInput = null;
		string sKey = null;
		string sHexIV = null;
		string sCorrect = null;
		byte[] aKey = null;
		byte[] aResult = null;
		byte[] aData = null;
		byte[] aInitV = null;

		sKey = "0123456789abcdeffedcba987654321089abcdef01234567";
		sHexIV = "1234567890abcdef";
		sInput = "Now is the time for all ";
		sCorrect = "204011f986e35647199e47af391620c5bb9a5bcfc86db0bb";

		// Convert hex strings to byte arrays
		aKey = Cnv.FromHex(sKey);
		aInitV = Cnv.FromHex(sHexIV);

		// Convert string to byte array 
		aData = System.Text.Encoding.Default.GetBytes(sInput);

		Console.WriteLine("KY=" + Cnv.ToHex(aKey));
		Console.WriteLine("IV=" + Cnv.ToHex(aInitV));
		Console.WriteLine("PT=" + "[" + sInput + "]");
		// Encrypt in one-off process
		aResult = Tdea.Encrypt(aData, aKey, Mode.CBC, aInitV);
		Console.WriteLine("CT=" + Cnv.ToHex(aResult) + " " + General.ErrorCode());
		Console.WriteLine("OK=" + sCorrect);

		// Now decrypt back
		aData = Tdea.Decrypt(aResult, aKey, Mode.CBC, aInitV);
		sOutput = System.Text.Encoding.Default.GetString(aData);
		Console.WriteLine("P'=" + "[" + sOutput + "]" + " " + General.ErrorCode());

	}

	public static void V_Test_TDEA_File()
	{
		Console.WriteLine("Testing TDEA_File ...");
		const string MY_PATH = "";
		byte[] aKey = null;
		string strFileOut = null;
		string strFileIn = null;
		string strFileChk = null;
		int nRet = 0;

		// Construct full path names to files
		strFileIn = MY_PATH + "hello.txt";
		strFileOut = MY_PATH + "hello.tdea.enc.dat";
		strFileChk = MY_PATH + "hello.tdea.chk.txt";

		// Create the key as an array of bytes
		// This creates an array of 24 bytes {&HFE, &HDC, ... &H10}
		aKey = Cnv.FromHex("fedcba9876543210fedcba9876543210fedcba9876543210");

		// Encrypt plaintext file to ciphertext
		// Output file = 16-byte ciphertext file hello.enc
		nRet = Tdea.FileEncrypt(strFileOut, strFileIn, aKey, Mode.ECB, null);
		Console.WriteLine("TDEA_File(ENCRYPT) returns " + nRet + "");

		// Now decrypt it
		nRet = Tdea.FileDecrypt(strFileChk, strFileOut, aKey, Mode.ECB, null);
		Console.WriteLine("TDEA_File(DECRYPT) returns " + nRet + "");

	}

	public static void V_Test_TDEA_HexMode()
	{
		Console.WriteLine("Testing TDEA_HexMode ...");
		string sOutput = null;
		string sInput = null;
		string sKey = null;
		string sInitV = null;
		string sCorrect = null;

		sInput = "5468697320736F6D652073616D706520636F6E74656E742E0808080808080808";
		//         T h i s _ s o m e _ s a m p e _ c o n t e n t . (padding 8 x 08)
		sKey = "737C791F25EAD0E04629254352F7DC6291E5CB26917ADA32";
		sInitV = "B36B6BFB6231084E";
		sCorrect = "d76fd1178fbd02f84231f5c1d2a2f74a4159482964f675248254223daf9af8e4";

		Console.WriteLine("KY=" + sKey);
		Console.WriteLine("PT=" + sInput);
		sOutput = Tdea.Encrypt(sInput, sKey, Mode.CBC, sInitV, EncodingBase.Base16);
		Console.WriteLine("CT=" + sOutput + " " + General.ErrorCode());
		Console.WriteLine("OK=" + sCorrect);

		sInput = sOutput;
		sOutput = Tdea.Decrypt(sInput, sKey, Mode.CBC, sInitV, EncodingBase.Base16);
		Console.WriteLine("P'=" + sOutput + " " + General.ErrorCode());

	}

	public static void V_Test_WIPE_File()
	{
		Console.WriteLine("Testing WIPE_File ...");
		bool isOK = false;
		isOK = Wipe.File("ToDelete.txt");
		Console.WriteLine("Wipe.File returns " + isOK + " (expected True)");

	}

	public static void V_Test_X509_CertExpiresOn()
	{
		Console.WriteLine("Testing X509_CertExpiresOn ...");
		string strCertName = null;
		string strDateTime = null;

		strCertName = "AliceRSASignByCarl.cer";
		strDateTime = X509.CertIssuedOn(strCertName);
		Console.WriteLine("X509_CertIssuedOn returns " + strDateTime.Length + " for " + strCertName + ": " + strDateTime);
		strDateTime = X509.CertExpiresOn(strCertName);
		Console.WriteLine("X509_CertExpiresOn returns " + strDateTime.Length + " for " + strCertName + ": " + strDateTime);

	}

	public static void V_Test_X509_CertIsValidNow()
	{
		Console.WriteLine("Testing X509_CertIsValidNow ...");
		bool isValid = false;
		string strCertName = null;

		strCertName = "myca.cer";
		isValid = X509.CertIsValidNow(strCertName);
		Console.WriteLine("X509_CertIsValidNow returns " + isValid + " for " + strCertName);

	}

	public static void V_Test_X509_CertRequest()
	{
		Console.WriteLine("Testing X509_CertRequest ...");
		int nRet = 0;
		nRet = X509.CertRequest("myreq.p10.txt", "mykey.epk", "CN=myuser,O=Test Org,C=AU,L=Sydney,S=NSW", "password", 0);
		if (nRet != 0) {
			Console.WriteLine(nRet + " " + General.LastError());
		}
		else {
			Console.WriteLine("Success");
		}

	}

	public static void V_Test_X509_CertRequest_2()
	{
		Console.WriteLine("Testing X509_CertRequest ...");
		int nRet = 0;
		nRet = X509.CertRequest("pkcs_ex_req.bin", "rsa508.epk", "C=US,O=Example Organization,CN=Test User 1", "password", X509.Options.SigAlg_Md2WithRSAEncryption | X509.Options.FormatBinary | X509.Options.RequestKludge);
		if (nRet != 0) {
			Console.WriteLine(nRet + " " + General.LastError());
		}
		else {
			Console.WriteLine("Success");
		}

	}

	public static void V_Test_X509_CertSerialNumber()
	{
		Console.WriteLine("Testing X509_CertSerialNumber ...");
		string strCertName = null;
		string strOutput = null;

		strCertName = "BobRSASignByCarl.cer";
		// Set dir to suit
		strOutput = X509.CertSerialNumber(strCertName);
		Console.WriteLine("X509_CertSerialNumber returns " + strOutput.Length + " for " + strCertName + ": " + strOutput);

	}

	public static void V_Test_X509_CertSubjectName()
	{
		Console.WriteLine("Testing X509_CertSubjectName ...");
		string strCertName = null;
		string strOutput = null;

		strCertName = "AAA010101AAAsd.cer";
		strOutput = X509.CertIssuerName(strCertName, "");
		Console.WriteLine("X509.CertIssuerName returns " + strOutput.Length + " for " + strCertName);
		Console.WriteLine("[" + strOutput + "]");

		strOutput = X509.CertSubjectName(strCertName, "");
		Console.WriteLine("X509.CertSubjectName returns " + strOutput.Length + " for " + strCertName);
		Console.WriteLine("[" + strOutput + "]");

	}

	public static void V_Test_X509_CertThumb()
	{
		Console.WriteLine("Testing X509_CertThumb ...");
		string strCertName = null;
		string strHexHash = null;

		strCertName = "AliceRSASignByCarl.cer";
		strHexHash = X509.CertThumb(strCertName, HashAlgorithm.Sha1);
		Console.WriteLine("X509_CertThumb returns " + strHexHash.Length + " for " + strCertName);
		Console.WriteLine(strHexHash);

	}


	public static void V_Test_X509_CheckCertInCRL()
	{
		Console.WriteLine("Testing X509_CheckCertInCRL ...");
		int nRet = 0;
		string strCrlFile = null;
		string strCertFile = null;
		string strDate = null;

		// Use test CRL and certs from RFC3280
		strCrlFile = "rfc3280bis_CRL.crl";
		// This cert has not been revoked.
		strCertFile = "rfc3280bis_cert1.cer";
		Console.WriteLine("CrlFile=" + strCrlFile);
		Console.WriteLine("CertFile=" + strCertFile);
		nRet = X509.CheckCertInCRL(strCertFile, strCrlFile, "", "");
		Console.WriteLine("X509_CheckCertInCRL returns " + nRet);
		if (nRet == X509.Revoked) {
			Console.WriteLine("CERT HAS BEEN REVOKED");
		}
		else if (nRet == 0) {
			Console.WriteLine("Cert has not been revoked");
		}
		else {
			Console.WriteLine("ERROR: " + General.ErrorCode() + ": " + General.LastError());
		}

		// This cert has been revoked.
		strCertFile = "rfc3280bis_cert2.cer";
		Console.WriteLine("CrlFile=" + strCrlFile);
		Console.WriteLine("CertFile=" + strCertFile);
		nRet = X509.CheckCertInCRL(strCertFile, strCrlFile, "", "");
		Console.WriteLine("X509_CheckCertInCRL returns " + nRet);
		if (nRet == X509.Revoked) {
			Console.WriteLine("CERT HAS BEEN REVOKED");
		}
		else if (nRet == 0) {
			Console.WriteLine("Cert has not been revoked");
		}
		else {
			Console.WriteLine("ERROR: " + General.ErrorCode() + ": " + General.LastError());
		}

		// But the same cert was not revoked as at 15:00 GMT on 19 November 2004
		strCertFile = "rfc3280bis_cert2.cer";
		strDate = "2004-11-19T15:00Z";
		Console.WriteLine("CrlFile=" + strCrlFile);
		Console.WriteLine("CertFile=" + strCertFile);
		Console.WriteLine("Date=" + strDate);
		nRet = X509.CheckCertInCRL(strCertFile, strCrlFile, "", strDate);
		Console.WriteLine("X509_CheckCertInCRL(" + strDate + ") returns " + nRet);
		if (nRet == X509.Revoked) {
			Console.WriteLine("CERT HAS BEEN REVOKED");
		}
		else if (nRet == 0) {
			Console.WriteLine("Cert has not been revoked");
		}
		else {
			Console.WriteLine("ERROR: " + General.ErrorCode() + ": " + General.LastError());
		}

	}

	public static void V_Test_X509_GetCertFromP7Chain()
	{
		Console.WriteLine("Testing X509_GetCertFromP7Chain ...");
		int nRet = 0;
		string strListFile = null;
		string strCertFile = null;
		int nCerts = 0;
		int iCert = 0;

		strListFile = "bob.p7b";
		// How many certificates?
		nCerts = X509.GetCertFromP7Chain("", strListFile, 0);
		Console.WriteLine("X509_GetCertFromP7Chain(0) returns " + nCerts + " for " + strListFile);
		// Enumerate through them all
		if (nCerts > 0) {
			for (iCert = 1; iCert <= nCerts; iCert++) {
				strCertFile = "bobcert" + iCert + ".cer";
				nRet = X509.GetCertFromP7Chain(strCertFile, strListFile, iCert);
				Console.WriteLine("X509_GetCertFromP7Chain(" + iCert + ") returns " + nRet + "->" + strCertFile);
			}
		}

	}

	public static void V_Test_X509_HashIssuerAndSN()
	{
		Console.WriteLine("Testing X509_HashIssuerAndSN ...");
		string strCertName = null;
		string strOutput = null;

		strCertName = "BobRSASignByCarl.cer";
		// Set dir to suit
		strOutput = X509.HashIssuerAndSN(strCertName, HashAlgorithm.Sha1);
		Console.WriteLine("X509_HashIssuerAndSN returns " + strOutput.Length + " for " + strCertName + ": " + strOutput);

	}

	public static void V_Test_X509_KeyUsageFlags()
	{
		Console.WriteLine("Testing X509_KeyUsageFlags ...");
		int nRet = 0;
		string strCertName = null;
		strCertName = "CarlRSASelf.cer";
		nRet = X509.KeyUsageFlags(strCertName);
		// Show the result as a hex number
		Console.WriteLine("keyUsage flags are (0x{0:X}):", nRet);
		// Check all the keyUsage flags in turn
		if ((nRet & (int)X509.KeyUsageOptions.DigitalSignature) != 0) Console.WriteLine("digitalSignature");
		if ((nRet & (int)X509.KeyUsageOptions.NonRepudiation) != 0) Console.WriteLine("nonRepudiation");
		if ((nRet & (int)X509.KeyUsageOptions.KeyEncipherment) != 0) Console.WriteLine("keyEncipherment");
		if ((nRet & (int)X509.KeyUsageOptions.DataEncipherment) != 0) Console.WriteLine("dataEncipherment");
		if ((nRet & (int)X509.KeyUsageOptions.KeyAgreement) != 0) Console.WriteLine("keyAgreement");
		if ((nRet & (int)X509.KeyUsageOptions.KeyCertSign) != 0) Console.WriteLine("keyCertSign");
		if ((nRet & (int)X509.KeyUsageOptions.CrlSign) != 0) Console.WriteLine("cRLSign");
		if ((nRet & (int)X509.KeyUsageOptions.EncipherOnly) != 0) Console.WriteLine("encipherOnly");
		if ((nRet & (int)X509.KeyUsageOptions.DecipherOnly) != 0) Console.WriteLine("decipherOnly"); 

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
		strSubjectPubKeyFile = "mykey.pub";
		strIssuerPriKeyFile = "myca.epk";
		strPassword = "password";
		//!!
		nCertNum = 0x101;
		nYearsValid = 4;
		strDistName = "CN=My User,O=Test Org,OU=Unit,C=AU,L=My Town,S=State,E=myuser@testorg.com";
		strEmail = "myuser@testorg.com";

		nRet = X509.MakeCert(strNewCertFile, strIssuerCert, strSubjectPubKeyFile, strIssuerPriKeyFile, nCertNum, nYearsValid, strDistName, strEmail, 0, strPassword, 
		0);
		if (nRet != 0) {
			Console.WriteLine(nRet + " " + General.LastError());
		}
		else {
			Console.WriteLine("Success, created X.509 cert " + strNewCertFile);
		}

	}

	public static void V_Test_X509_MakeCertSelf()
	{
		Console.WriteLine("Testing X509_MakeCertSelf ...");
		int nRet = 0;
		X509.KeyUsageOptions kuoKeyUsage = default(X509.KeyUsageOptions);

		kuoKeyUsage = X509.KeyUsageOptions.DigitalSignature | X509.KeyUsageOptions.KeyCertSign | X509.KeyUsageOptions.CrlSign;
		nRet = X509.MakeCertSelf("myca.cer", "myca.epk", 99, 10, "CN=My CA,O=Test Org,OU=Certificate Services", "", kuoKeyUsage, "password", 0);
		if (nRet != 0) {
			Console.WriteLine(nRet + " " + General.LastError());
		}
		else {
			Console.WriteLine("Success");
		}

	}

	public static void V_Test_X509_MakeCertSelf_2()
	{
		Console.WriteLine("Testing X509_MakeCertSelf ...");
		int nRet = 0;
		X509.KeyUsageOptions kuoKeyUsage = default(X509.KeyUsageOptions);
		string strDN = null;

		// Specify DN using chinese characters in UTF-8
		// CN=da wei (U+5927, U+536B)
		// C=zhong guo (U+4E2D, U+56FD)
		strDN = "CN=#xE5A4A7E58DAB,C=#xe4b8ade59bbd";
		kuoKeyUsage = X509.KeyUsageOptions.DigitalSignature | X509.KeyUsageOptions.KeyCertSign | X509.KeyUsageOptions.CrlSign;
		nRet = X509.MakeCertSelf("myca-chinadavid.cer", "myca.epk", 0x888, 4, strDN, "", kuoKeyUsage, "password", X509.Options.UTF8String);
		if (nRet != 0) {
			Console.WriteLine(nRet + " " + General.LastError());
		}
		else {
			Console.WriteLine("Success");
		}

	}

	public static void V_Test_X509_MakeCRL()
	{
		Console.WriteLine("Testing X509_MakeCRL ...");
		int nRet = 0;
		string strCrlFile = null;
		string strIssuerFile = null;
		string strKeyFile = null;
		string strPassword = null;
		string strCertList = null;
		string strExtension = null;
		// Create a new CRL dated with the current system time
		strCrlFile = "CarlsNew.crl";
		strIssuerFile = "CarlRSASelf.cer";
		strKeyFile = "CarlPrivRSASign.epk";
		// CAUTION: DO NOT HARD-CODE REAL PASSWORDS!
		strPassword = "password";
		strCertList = "1,2007-12-31, 2, 2009-12-31T12:59:59Z, 66000,2066-01-01, #x0102deadbeef,2010-02-28T01:01:59";
		nRet = X509.MakeCRL(strCrlFile, strIssuerFile, strKeyFile, strPassword, strCertList, "", 0);
		Console.WriteLine("X509_MakeCRL returns " + nRet + " (expected 0)");
		if ((nRet == 0)) {
			Console.WriteLine("SUCCESS: New CRL file '" + strCrlFile + "' created.");
		}
		else {
			Console.WriteLine("ERROR: " + General.ErrorLookup(nRet) + ": " + General.LastError());
		}
		// Create another CRL using specified times (NB these are GMT times, not local)
		strExtension = "thisUpdate=2010-04-01T12:00,nextUpdate=2010-05-01";
		strCrlFile = "Carl_20100401.crl";
		nRet = X509.MakeCRL(strCrlFile, strIssuerFile, strKeyFile, strPassword, strCertList, strExtension, 0);
		Console.WriteLine("X509_MakeCRL returns " + nRet + " (expected 0)");
		if ((nRet == 0)) {
			Console.WriteLine("SUCCESS: New CRL file '" + strCrlFile + "' created.");
		}
		else {
			Console.WriteLine("ERROR: " + General.ErrorLookup(nRet) + ": " + General.LastError());
		}

	}

	public static void V_Test_X509_TextDump()
	{
		Console.WriteLine("Testing X509_TextDump ...");
		int nRet = 0;
		string strInputFile = null;
		string strOutFile = null;

		strInputFile = "AliceRSASignByCarl.cer";
		strOutFile = "dump-AliceRSASignByCarl.cer.txt";
		Console.WriteLine("File=" + strInputFile);
		nRet = X509.TextDump(strOutFile, strInputFile);
		Console.WriteLine("X509_TextDump returns " + nRet);

	}

	public static void V_Test_X509_ValidatePath()
	{
		Console.WriteLine("Testing X509_ValidatePath ...");
		int nRet = 0;
		string strP7cFile = null;
		string strTrustedCert = null;
		string strCertList = null;

		// A p7c "certs-only" file which includes a self-signed cert
		strP7cFile = "testcerts1.p7c";
		nRet = X509.ValidatePath(strP7cFile, "", false);
		Console.WriteLine("X509_ValidatePath returns " + nRet + " (expected 0)");

		// Same again but specify the trusted root cert
		// (which is the same as the self-signed cert in the p7c file)
		strP7cFile = "testcerts1.p7c";
		strTrustedCert = "testcert00.cer";
		nRet = X509.ValidatePath(strP7cFile, strTrustedCert, false);
		Console.WriteLine("X509_ValidatePath returns " + nRet + " (expected 0)");

		// Specify a cert list - testcert00.cer is the self-signed cert
		strCertList = "testcert00.cer;testcert03.cer;testcert01.cer;testcert02.cer";
		nRet = X509.ValidatePath(strCertList, "", false);
		Console.WriteLine("X509_ValidatePath returns " + nRet + " (expected 0)");

		// Same again but specify the trusted root cert (this time it is not in the list)
		strCertList = "testcert01.cer;testcert02.cer;testcert03.cer";
		strTrustedCert = "testcert00.cer";
		nRet = X509.ValidatePath(strCertList, strTrustedCert, false);
		Console.WriteLine("X509_ValidatePath returns " + nRet + " (expected 0)");

	}

	public static void V_Test_X509_VerifyCert()
	{
		Console.WriteLine("Testing X509_VerifyCert ...");
		// Returns 0 if OK, -1 if fails to validate, or +ve other error
		int nRet = 0;
		nRet = X509.VerifyCert("myuser.cer", "myca.cer");
		if (nRet == 0) {
			Console.WriteLine("Verification is OK");
		}
		else if (nRet > 0) {
			Console.WriteLine("Error: " + nRet + General.LastError());
		}
		else {
			Console.WriteLine("Cert not issued by this Issuer");
		}

	}


	public static void Main()
	{
		string subdir = null;
		Console.WriteLine("CryptoSys PKI Version={0}", General.Version());
		subdir = SetupTestFiles();
		if (subdir.Length == 0) return; 
		V_Test_CIPHER_Bytes();
		V_Test_CIPHER_File();
		V_Test_CIPHER_Hex();
		V_Test_CIPHER_KeyWrap();
		V_Test_CIPHER_KeyUnwrap();
		V_Test_CMS_GetSigDataDigest();
		V_Test_CMS_GetSigDataDigest_2();
		V_Test_CMS_MakeDetachedSig();
		V_Test_CMS_MakeEnvData();
		V_Test_CMS_MakeEnvData_2();
		V_Test_CMS_MakeEnvData_3();
		V_Test_CMS_MakeEnvDataFromString();
		V_Test_CMS_MakeSigData();
		V_Test_CMS_MakeSigData_2();
		V_Test_CMS_MakeSigDataFromSigValue();
		V_Test_CMS_ReadEnvData();
		V_Test_CMS_ReadEnvDataToString();
		V_Test_CMS_ReadSigData();
		V_Test_CMS_ReadSigDataToString();
		V_Test_CMS_VerifySigData();
		V_Test_CNV_ByteEncoding();
		V_Test_CNV_UTF8BytesFromLatin1();
		V_Test_HASH_Bytes();
		V_Test_HASH_File();
		V_Test_HASH_HexFromBytes();
		V_Test_HASH_HexFromBytes_2();
		V_Test_HASH_HexFromFile();
		V_Test_HASH_HexFromHex();
		V_Test_HMAC_Bytes();
		V_Test_HMAC_HexFromBytes();
		V_Test_HMAC_HexFromHex();
		V_Test_OCSP_MakeRequest();
		V_Test_OCSP_ReadResponse();
		V_Test_PEM_FileFromBinFile();
		V_Test_PEM_FileToBinFile();
		V_Test_PFX_MakeFile();
		V_Test_PFX_MakeFile_2();
		V_Test_PKI_CompileTime();
		V_Test_PKI_ErrorLookup();
		V_Test_PKI_LicenceType();
		V_Test_PKI_ModuleName();
		V_Test_PKI_PowerUpTests();
		V_Test_PKI_Version();
		// Uncomment the next line to test the Pwd.Prompt method
		//V_Test_PWD_PromptEx()
		V_Test_RNG_Bytes();
		// Uncomment the next line to test the Rng.BytesWithPrompt method
		//V_Test_RNG_BytesWithPrompt()
		V_Test_RNG_Initialize();
		V_Test_RNG_Number();
		V_Test_RNG_Test();
		V_Test_RSA_DecodeMsg();
		V_Test_RSA_EncodeMsg();
		V_Test_RSA_FromXMLString();
		V_Test_RSA_FromXMLString_2();
		V_Test_RSA_GetPublicKeyFromCert();
		V_Test_RSA_KeyMatch();
		V_Test_RSA_MakeKeys();
		V_Test_RSA_RawPrivate();
		V_Test_RSA_RawPublic();
		V_Test_RSA_ReadPrivateKeyInfo();
		V_Test_RSA_SaveEncPrivateKey();
		V_Test_RSA_SavePrivateKeyInfo();
		V_Test_RSA_ToXMLString();
		V_Test_RSA_PublicKeyFromPrivate();
		V_Test_RSA_ReadPrivateKeyFromPFX();
		V_Test_TDEA_B64Mode();
		V_Test_TDEA_BytesMode();
		V_Test_TDEA_File();
		V_Test_TDEA_HexMode();
		V_Test_WIPE_File();
		V_Test_X509_CertExpiresOn();
		V_Test_X509_CertIsValidNow();
		V_Test_X509_CertRequest();
		V_Test_X509_CertRequest_2();
		V_Test_X509_CertSerialNumber();
		V_Test_X509_CertSubjectName();
		V_Test_X509_CertThumb();
		V_Test_X509_CheckCertInCRL();
		V_Test_X509_GetCertFromP7Chain();
		V_Test_X509_HashIssuerAndSN();
		V_Test_X509_KeyUsageFlags();
		V_Test_X509_MakeCert();
		V_Test_X509_MakeCertSelf();
		V_Test_X509_MakeCertSelf_2();
		V_Test_X509_MakeCRL();
		V_Test_X509_TextDump();
		V_Test_X509_ValidatePath();
		V_Test_X509_VerifyCert();

		Console.WriteLine("ALL DONE.");
		DeleteSetupDir(subdir);
	}

	private static string SetupTestFiles()
	{
		string subdir = null;
		// Required test files
		string[] arrFileNames = new string[] { "hello.txt", "DetSignByAlice.bin", "4.2.bin", "AlicePrivRSASign.epk", "AliceRSASignByCarl.cer", "excontent.txt", "BobRSASignByCarl.cer", "CarlRSASelf.cer", "AlicePrivRSASign.pri", "BobPrivRSAEncrypt.epk", 
		"UTNUSERFirst-Object.cer", "dims.cer", "ocsp_response_ok_dims.dat", "smallca.cer", "bob.cer", "seed.dat", "AAA010101AAAsd.cer", "AAA010101AAA_0408021316S.key", "rsa508.epk", "rsa508.pub", 
		"BobPrivRSAEncrypt.pri", "CarlPrivRSASign.pri", "ToDelete.txt", "myca.cer", "mykey.epk", "rfc3280bis_CRL.crl", "rfc3280bis_cert1.cer", "rfc3280bis_cert2.cer", "bob.p7b", "myca.epk", 
		"testcerts1.p7c", "testcert00.cer", "testcert01.cer", "testcert02.cer", "testcert03.cer", "myuser.cer" };
		//**************************************************
		// Check we have required files in current directory *
		//**************************************************
		string currentDir = System.IO.Directory.GetCurrentDirectory();
		Console.WriteLine("Current directory is '{0}'.", currentDir);
		Console.WriteLine("Checking required test files are in current directory...");
		string missingFile = "STOPPED: Required file is missing." + "\n" + " Look in pkiExamplesTestFiles.zip";
		foreach (string fn in arrFileNames) {
			if (FileIsNotPresent(fn, missingFile)) {
				return "";
			}
		}

		//*************************************************
		// Create a test sub-directory with a random name, 
		// copy these test files to it, and work in that sub-directory
		//*************************************************
		subdir = "pkitest." + Cnv.ToHex(Rng.Bytes(4));
		Console.WriteLine("Creating test sub-directory '{0}'", subdir);
		System.IO.Directory.CreateDirectory(subdir);
		// Copy test files
		foreach (string fn in arrFileNames) {
			System.IO.File.Copy(fn, subdir + "\\" + fn, true);
		}
		// Change current working directory to sub-dir
		System.IO.Directory.SetCurrentDirectory(subdir);
		Console.WriteLine("CWD is " + System.IO.Directory.GetCurrentDirectory());
		return subdir;

	}

	private static void DeleteSetupDir(string subdir)
	{
		//*********************************************************
		// Put CWD back to parent and remove the test dir
		//*********************************************************
		System.IO.Directory.SetCurrentDirectory("..");
		Console.WriteLine("\n" + "CWD reset to " + System.IO.Directory.GetCurrentDirectory());
		// Remove directory
		Console.WriteLine("Removing test directory...");
		System.IO.Directory.Delete(subdir, true);

	}

	private static bool FileExists(string filePath)
	{
		FileInfo fi = new FileInfo(filePath);
		return fi.Exists;
	}

	private static bool FileIsNotPresent(string filePath, string message)
	{
		if (!FileExists(filePath)) {
			Console.WriteLine("\n" + "{0}: {1}", message, filePath);
			return true;
		}
		return false;
	}

}
