using System;
using System.Runtime.InteropServices;
using System.Text;


/* CryptoSys PKI Pro interface for .NET.
 * 
 * This code is provided as a suggested .NET interface to CryptoSys PKI Pro.
 * Please report any bugs to <http://www.di-mgt.com.au/contact>
 */

/*  $Id: CryptoSysPKI.cs $ 
 *   Last updated:
 *   $Date: 2017-08-08 15:29:00 $
 *   $Version: 11.2.0 $
 */

/**************************** COPYRIGHT NOTICE********************************
 * Copyright (C) 2005-17 David Ireland, DI Management Services Pty Limited. 
 * All rights reserved. <www.di-mgt.com.au> <www.cryptosys.net>
 * This code is provided 'as-is' without any express or implied warranty.
 * Free license is hereby granted to use this code as part of an application
 * provided this copyright notice is left intact. You are *not* licensed to 
 * share any of this code in any form of mass distribution, including, but not
 * limited to, reposting on other web sites or in any source code repository.
************************ END OF COPYRIGHT NOTICE******************************
*/


namespace CryptoSysPKI
{
	/// <summary>
	/// Cipher Mode
	/// </summary>
	public enum Mode
	{
		/// <summary>
		/// Electronic Code Book mode
		/// </summary>
		ECB = 0x000,
		/// <summary>
		/// Cipher Block Chaining mode
		/// </summary>
		CBC = 0x100,
		/// <summary>
		/// Output Feedback mode
		/// </summary>
		OFB = 0x200,
		/// <summary>
		/// Cipher Feedback mode
		/// </summary>
		CFB = 0x300,
		/// <summary>
		/// Counter mode
		/// </summary>
		CTR = 0x400,
	}

	/// <summary>
	/// Block Cipher Algorithm
	/// </summary>
	public enum CipherAlgorithm
	{
		/// <summary>
		/// Triple DES (TDEA, 3DES, des-ede3)
		/// </summary>
		Tdea = 0x10,
		/// <summary>
		/// AES-128
		/// </summary>
		Aes128 = 0x20,
		/// <summary>
		/// AES-192
		/// </summary>
		Aes192 = 0x30,
		/// <summary>
		/// AES-256
		/// </summary>
		Aes256 = 0x40,
	}

	/// <summary>
	/// Block Cipher Padding
	/// </summary>
	public enum Padding
	{
		/// <summary>
		/// Use default padding
		/// </summary>
		Default = 0x0,
		/// <summary>
		/// No padding is added
		/// </summary>
		NoPad = 0x10000,
		/// <summary>
		/// The padding scheme described in PKCS#5
		/// </summary>
		Pkcs5 = 0x20000,
		/// <summary>
		/// Pads with 0x80 followed by as many zero bytes necessary to fill the block
		/// </summary>
		OneAndZeroes = 0x30000,
		/// <summary>
		/// The padding scheme described in ANSI X9.23
		/// </summary>
		AnsiX923 = 0x40000,
		/// <summary>
		/// The padding scheme described in W3C https://www.w3.org/TR/xmlenc-core1/#sec-Padding
		/// </summary>
		W3CPadding = 0x50000,
	}

	/// <summary>
	/// Base for encoding methods
	/// </summary>
	public enum EncodingBase
	{
		/// <summary>
		/// Base64 encoding
		/// </summary>
		Base64,
		/// <summary>
		/// Base16 encoding (i.e. hexadecimal)
		/// </summary>
		Base16,
	}

	/// <summary>
	/// Message Digest Hash Algorithm
	/// </summary>
	public enum HashAlgorithm
	{
		/// <summary>
		/// SHA-1 (as per FIPS PUB 180-4)
		/// </summary>
		Sha1 = 0,
		/// <summary>
		/// MD5 (as per RFC 1321)
		/// </summary>
		Md5 = 1,
		/// <summary>
		/// MD2 (as per RFC 1319) Not recommended: for legacy applications only.
		/// </summary>
		Md2 = 2,
		/// <summary>
		/// SHA-224 (as per FIPS PUB 180-4)
		/// </summary>
		Sha224 = 6,
		/// <summary>
		/// SHA-256 (as per FIPS PUB 180-4)
		/// </summary>
		Sha256 = 3,
		/// <summary>
		/// SHA-384 (as per FIPS PUB 180-4)
		/// </summary>
		Sha384 = 4,
		/// <summary>
		/// SHA-512 (as per FIPS PUB 180-4)
		/// </summary>
		Sha512 = 5,
		/// <summary>
		/// RIPEMD-160
		/// </summary>
		Ripemd160 = 7,
		/// <summary>
		/// RIPEMD-160 hash of a SHA-256 hash (<c>RIPEMD160(SHA256(m))</c>)
		/// </summary>
		Bitcoin160 = 8,
	}

	/// <summary>
	/// Signature algorithm
	/// </summary>
	public enum SigAlgorithm
	{
		/// <summary>
		/// Use default signature algorithm [rsa-sha1/sha1WithRSAEncryption]
		/// </summary>
		Default = 0,
		/// <summary>
		/// Use sha1WithRSAEncryption (rsa-sha1) signature algorithm
		/// </summary>
		Rsa_Sha1 = SigAlg.PKI_SIG_SHA1RSA,
		/// <summary>
		/// Use sha224WithRSAEncryption (rsa-sha224) signature algorithm
		/// </summary>
		Rsa_Sha224 = SigAlg.PKI_SIG_SHA224RSA,
		/// <summary>
		/// Use sha256WithRSAEncryption (rsa-sha256) signature algorithm
		/// </summary>
		Rsa_Sha256 = SigAlg.PKI_SIG_SHA256RSA,
		/// <summary>
		/// Use sha384WithRSAEncryption (rsa-sha384) signature algorithm
		/// </summary>
		Rsa_Sha384 = SigAlg.PKI_SIG_SHA384RSA,
		/// <summary>
		/// Use sha512WithRSAEncryption (rsa-sha512) signature algorithm
		/// </summary>
		Rsa_Sha512 = SigAlg.PKI_SIG_SHA512RSA,
		/// <summary>
		/// Use md5WithRSAEncryption (rsa-md5) signature algorithm (for legacy applications - not recommended for new implementations)
		/// </summary>
		Rsa_Md5 = SigAlg.PKI_SIG_MD5RSA,
		/// <summary>
		/// Use ecdsaWithSHA1 (ecdsa-sha1) signature algorithm
		/// </summary>
		Ecdsa_Sha1 = SigAlg.PKI_SIG_ECDSA_SHA1,
		/// <summary>
		/// Use ecdsaWithSHA224 (ecdsa-sha224) signature algorithm
		/// </summary>
		Ecdsa_Sha224 = SigAlg.PKI_SIG_ECDSA_SHA224,
		/// <summary>
		/// Use ecdsaWithSHA256 (ecdsa-sha256) signature algorithm
		/// </summary>
		Ecdsa_Sha256 = SigAlg.PKI_SIG_ECDSA_SHA256,
		/// <summary>
		/// Use ecdsaWithSHA384 (ecdsa-sha384) signature algorithm
		/// </summary>
		Ecdsa_Sha384 = SigAlg.PKI_SIG_ECDSA_SHA384,
		/// <summary>
		/// Use ecdsaWithSHA512 (ecdsa-sha512) signature algorithm
		/// </summary>
		Ecdsa_Sha512 = SigAlg.PKI_SIG_ECDSA_SHA512,
	}
	
	// Constants we use internally
	enum Direction
	{
		Encrypt = 1,
		Decrypt = 0
	}
	enum HashLen
	{
		PKI_SHA1_BYTES   =  20,
		PKI_SHA224_BYTES =  28,
		PKI_SHA256_BYTES =  32,
		PKI_SHA384_BYTES =  48,
		PKI_SHA512_BYTES =  64,
		PKI_MD5_BYTES    =  16,
		PKI_MD2_BYTES    =  16,
		PKI_RMD160_BYTES =  20,
		PKI_BTC160_BYTES =  20,

		PKI_MAX_HASH_BYTES = 64,

		//PKI_SHA1_CHARS   =  40,
		//PKI_SHA224_CHARS =  56,
		//PKI_SHA256_CHARS =  64,
		//PKI_SHA384_CHARS =  96,
		//PKI_SHA512_CHARS =  128,
		//PKI_MD5_CHARS    =  32,
		//PKI_MD2_CHARS    =  32,
		//PKI_RMD160_CHARS =  40,
		//PKI_BTC160_CHARS =  40,

		PKI_MAX_HASH_CHARS = 128
	}
	enum Emsig
	{
		PKI_EMSIG_DEFAULT = 0x20,
		PKI_EMSIG_DIGESTONLY = 0x1000,
		PKI_EMSIG_DIGINFO = 0x2000,
		PKI_EMSIG_ISO9796 = 0x100000,
	}
	enum myQuery
	{
		PKI_QUERY_GETTYPE = 0x100000,
		PKI_QUERY_NUMBER = 1,
		PKI_QUERY_STRING = 2,
	}
	enum SigAlg
	{
		PKI_SIG_SHA1RSA = 0,
		PKI_SIG_MD5RSA = 1,
		PKI_SIG_SHA256RSA = 3,
		PKI_SIG_SHA384RSA = 4,
		PKI_SIG_SHA512RSA = 5,
		PKI_SIG_SHA224RSA = 6,
		PKI_SIG_ECDSA_SHA1 = 0x10,
		PKI_SIG_ECDSA_SHA224 = 0x20,
		PKI_SIG_ECDSA_SHA256 = 0x30,
		PKI_SIG_ECDSA_SHA384 = 0x40,
		PKI_SIG_ECDSA_SHA512 = 0x50,
	}


	/// <summary>
	/// General info about the core DLL and errors returned by it.
	/// </summary>
	public class General
	{
		private const int PKI_GEN_PLATFORM = 0x40;

		private General()
		{}	// Static methods only, so hide constructor.

		/* GENERAL FUNCTIONS */
		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int PKI_LicenceType(int reserved);
		/// <summary>
		/// Return licence type.
		/// </summary>
		/// <returns>D=Developer T=Trial</returns>
		public static char LicenceType()
		{
			int n = PKI_LicenceType(0);
			char ch = (char)n;
			return ch;
		}
		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int PKI_LastError(StringBuilder sbErrMsg, int nMsgLen);
		/// <summary>
		/// Retrieve the last error message set by the toolkit.
		/// </summary>
		/// <returns>Final error message from last call (may be empty)</returns>
		public static string LastError()
		{
			StringBuilder sb = new StringBuilder(0);
			int n = PKI_LastError(null, 0);
			sb = new StringBuilder(n);
			PKI_LastError(sb, sb.Capacity);
			return sb.ToString();
		}
		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int PKI_ErrorCode();
		/// <summary>
		/// Return the <see cref="General.ErrorLookup">error code</see> of the <em>first</em> error that occurred when calling the last function.
		/// </summary>
		/// <returns>Error code</returns>
		public static int ErrorCode()
		{
			int n = PKI_ErrorCode();
			return n;
		}
		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int PKI_ErrorLookup(StringBuilder sbErrMsg, int nMsgLen, int nErrCode);
		/// <summary>
		/// Return a description of an error code.
		/// </summary>
		/// <param name="errCode">Code number</param>
		/// <returns>Corresponding error message</returns>
		public static string ErrorLookup(int errCode)
		{
			StringBuilder sb = new StringBuilder(128);
			if (PKI_ErrorLookup(sb, sb.Capacity, errCode)>0)
				return sb.ToString();
			else
				return String.Empty;
		}
		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int PKI_CompileTime(StringBuilder sbTimestamp, int nLen);
		/// <summary>
		/// Return date and time the core CryptoSys PKI DLL was last compiled.
		/// </summary>
		/// <returns>Date and time string</returns>
		public static string CompileTime()
		{
			StringBuilder sb = new StringBuilder(64);
			PKI_CompileTime(sb, sb.Capacity);
			return sb.ToString();
		}

		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int PKI_ModuleName(StringBuilder sbModuleName, int nLen, int reserved);
		/// <summary>
		/// Return full path name of core CryptoSys PKI DLL module.
		/// </summary>
		/// <returns>File name</returns>
		public static string ModuleName()
		{
			StringBuilder sb = new StringBuilder(0);
			int n = PKI_ModuleName(sb, 0, 0);
			sb = new StringBuilder(n);
			PKI_ModuleName(sb, sb.Capacity, 0);
			return sb.ToString();
		}
		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int PKI_PowerUpTests(int nOptions);
		/// <summary>
		/// Perform FIPS-140-2 start-up tests.
		/// </summary>
		/// <returns>Zero on success</returns>
		public static int PowerUpTests()
		{
			return PKI_PowerUpTests(0);
		}

		// Note the fudge here to avoid "unsafe" pointers to ints
		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int PKI_Version(byte[] dummyMajor, byte[] dummyMinor);
		/// <summary>
		/// Return the release version of the core CryptoSys PKI DLL as an integer value.
		/// </summary>
		/// <returns>Version number in form Major * 10000 + Minor * 100 + Release. For example, version 3.10.1 would return 31001.</returns>
		public static int Version()
		{
			int n = PKI_Version(null, null);
			return n;
		}

		/// <summary>
		/// Returns flag indicating the platform of the core DLL.
		/// </summary>
		/// <returns>1 if platform is Win64 (X64) or 0 if Win32</returns>
		public static int IsWin64()
		{
			return PKI_LicenceType(PKI_GEN_PLATFORM);
		}

		// [v11.2] Changed to use specific PKI_Platform function 
		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int PKI_Platform(StringBuilder sbOutput, int nOutChars);

		/// <summary>
		/// Return the platform of the core DLL.
		/// </summary>
		/// <returns><c>"Win32"</c> or <c>"X64"</c></returns>
		public static string Platform()
		{
			StringBuilder sb = new StringBuilder(0);
			int n = PKI_Platform(sb, 0);
			sb = new StringBuilder(n);
			PKI_Platform(sb, sb.Capacity);
			return sb.ToString();
		}
	}

	/// <summary>
	/// Create, read and analyze Cryptographic Message Syntax (CMS) objects.
	/// </summary>
	public class Cms
	{
		private Cms()
		{ }	// Static methods only, so hide constructor.

		private const int PKI_CMS_FORMAT_BASE64 = 0x10000;

		/// <summary>
		/// Options for CMS objects
		/// </summary>
		[Flags()]
		public enum Options
		{
			/// <summary>
			/// Default option
			/// </summary>
			Default = 0,
			/// <summary>
			/// Exclude X.509 certs from output (sig-data only).
			/// </summary>
			ExcludeCerts = 0x0100,
			/// <summary>
			/// Exclude data from output (sig-data only).
			/// </summary>
			ExcludeData = 0x0200,
			/// <summary>
			/// Create a "certs-only" PKCS#7 certficate chain (sig-data only).
			/// </summary>
			CertsOnly = 0x0400,
			/// <summary>
			/// Include Signed Attributes (sig-data only).
			/// </summary>
			IncludeAttributes = 0x0800,
			/// <summary>
			/// Add signing time (sig-data only).
			/// </summary>
			AddSignTime = 0x1000,
			/// <summary>
			/// Add S/MIME capabilities (sig-data only).
			/// </summary>
			AddSmimeCapabilities = 0x2000,
			/// <summary>
			/// Create output/expect input in base64 format [default = binary]
			/// </summary>
			FormatBase64 = 0x10000,
			/// <summary>
			/// Use MD5 hash digest algorithm (sig-data only) [default = SHA-1]
			/// </summary>
			UseMD5 = HashAlgorithm.Md5,
			/// <summary>
			/// Create a "naked" SignedData object with no outerContentInfo as permitted by PKCS#7 v1.6
			/// </summary>
			NoOuter = 0x2000000,
			/// <summary>
			/// Use alternative (non-standard) signature algorithm identifiers, e.g. 'sha1withRSAEncryption' instead of 'rsaEncryption'
			/// </summary>
			AltAlgId = 0x4000000,
			/// <summary>
			/// Use to speed up the encryption of large files [new in v3.7]
			/// </summary>
			BigFile = 0x8000000,
		}
		/// <summary>
		/// Advanced options for CMS enveloped-data objects
		/// </summary>
		[Flags()]
		public enum EnvDataOptions
		{
			// Later: KDF2, KDF3, MGF1, etc
			/// <summary>
			/// Default option
			/// </summary>
			None = 0,
			/// <summary>
			/// Object is encoded in base64
			/// </summary>
			FormatBase64 = PKI_CMS_FORMAT_BASE64,
			/// <summary>
			/// Use alternative (non-standard) alternative TeleTrusT Content Encryption Algorithm Identifier
			/// </summary>
			AltAlgId = 0x4000000,
			/// <summary>
			/// Use to speed up the encryption of large files [new in v3.7]
			/// </summary>
			BigFile = 0x8000000,
		}
		/// <summary>
		/// Advanced options for CMS signed-data objects
		/// </summary>
		[Flags()]
		public enum SigDataOptions
		{
			/// <summary>
			/// Default option
			/// </summary>
			Default = 0,
			/// <summary>
			/// Exclude X.509 certs from output.
			/// </summary>
			ExcludeCerts = 0x0100,
			/// <summary>
			/// Exclude data from output.
			/// </summary>
			ExcludeData = 0x0200,
			/// <summary>
			/// Create a "certs-only" PKCS#7 certficate chain.
			/// </summary>
			CertsOnly = 0x0400,
			/// <summary>
			/// Include Signed Attributes.
			/// </summary>
			IncludeAttributes = 0x0800,
			/// <summary>
			/// Add signing time.
			/// </summary>
			AddSignTime = 0x1000,
			/// <summary>
			/// Add S/MIME capabilities.
			/// </summary>
			AddSmimeCapabilities = 0x2000,
			/// <summary>
			/// Create output/expect input in base64 format [default = binary]
			/// </summary>
			FormatBase64 = 0x10000,
			/// <summary>
			/// Create a "naked" SignedData object with no outerContentInfo as permitted by PKCS#7 v1.6
			/// </summary>
			NoOuter = 0x2000000,
			/// <summary>
			/// Use alternative (non-standard) signature algorithm identifiers, e.g. 'sha1withRSAEncryption' instead of 'rsaEncryption'
			/// </summary>
			AltAlgId = 0x4000000,
			/// <summary>
			/// Use to speed up the processing of large files [new in v10.0]
			/// </summary>
			BigFile = 0x8000000,
		}

		/// <summary>
		/// Advanced options for CMS compressed-data objects
		/// </summary>
		[Flags()]
		public enum ComprDataOptions
		{
			/// <summary>
			/// Default option
			/// </summary>
			Default = 0,
			/// <summary>
			/// Extract the compressed data as is without inflation
			/// </summary>
			NoInflate = 0x1000000,
		}

		/// <summary>
		/// Key encryption algorithm
		/// </summary>
		/// <remarks>This is intended for future use. Only <c>rsaEncryption</c> is currently available.</remarks>
		public enum KeyEncrAlgorithm
		{
			/// <summary>
			/// Default <c>rsaEncryption</c>.
			/// </summary>
			Default = 0x0,
			/// <summary>
			/// <c>rsaEncryption</c> from PKCS#1 v1.5.
			/// </summary>
			Rsa_Pkcs1v1_5 = 0x0000,
			//
			// (0x1000 is reserved for RSAES-OAEP)
			//
			/* [RSA-KEM withdrawn in v3.4]
			/// <summary>
			/// RSA-KEM key transport algorithm from ISO-18033-2.
			/// </summary>
			Rsa_Kem = 0x2000,
			*/
		}

		/* RFC3852 CRYPTOGRAPHIC MESSAGE SYNTAX FUNCTIONS */
		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int CMS_MakeEnvData(string strFileOut, string strFileIn,
			string strCertList, string sSeed, int nSeedLen, int nOptions);
		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int CMS_MakeEnvDataFromString(string strFileOut, string strDataIn,
			string strCertList, string sSeed, int nSeedLen, int nOptions);

		/// <overloads>Creates an encrypted CMS enveloped-data object</overloads>
		/// <summary>
		/// Creates an encrypted CMS enveloped-data object for one or more recipients using their x.509 certificates
		/// (default algorithms).
		/// </summary>
		/// <param name="outputFile">Output file to be created</param>
		/// <param name="inputFile">Input data file</param>
		/// <param name="certList">List of X509 certificate filename(s), separated by semi-colons</param>
		/// <param name="options">Option flags: set as zero for defaults.</param>
		/// <returns>Number of successful recipients or a negative <see cref="General.ErrorLookup">error code</see>.</returns>
		/// <remarks>This uses the default key-encryption algorithm <c>rsaEncryption</c>
		/// with triple DES <c>des-ede3-cbc</c> for content encryption.
		/// It is an error if any specified certificate file in <c>certList</c> is missing or corrupted.
		/// </remarks>
		public static int MakeEnvData(string outputFile, string inputFile,
			string certList, Cms.Options options)
		{
			int flags = (int)options;
			int r = CMS_MakeEnvData(outputFile, inputFile, certList, "", 0, flags);
			return r;
		}

		/// <summary>
		/// Creates an encrypted CMS enveloped-data object for one or more recipients using their x.509 certificates 
		/// (alternative content encryption algorithm).
		/// </summary>
		/// <param name="outputFile">Output file to be created</param>
		/// <param name="inputFile">Input data file</param>
		/// <param name="certList">List of X509 certificate filename(s), separated by semi-colons</param>
		/// <param name="cipherAlg">Content encryption algorithm [default=Triple DES]</param>
		/// <param name="advOptions">Advanced options. See <see cref="Cms.EnvDataOptions"/>.</param>
		/// <returns>Number of successful recipients or a negative <see cref="General.ErrorLookup">error code</see>.</returns>
		public static int MakeEnvData(string outputFile, string inputFile,
			string certList, CipherAlgorithm cipherAlg, EnvDataOptions advOptions)
		{
			int flags = (int)advOptions | (int)cipherAlg;
			int r = CMS_MakeEnvData(outputFile, inputFile, certList, "", 0, flags);
			return r;
		}

		/// <summary>
		/// Creates an encrypted CMS enveloped-data object for one or more recipients using their x.509 certificates 
		/// [superflous].
		/// </summary>
		/// <param name="outputFile">Output file to be created</param>
		/// <param name="inputFile">Input data file</param>
		/// <param name="certList">List of X509 certificate filename(s), separated by semi-colons</param>
		/// <param name="cipherAlg">Content encryption algorithm [default=Triple DES]</param>
		/// <param name="keyEncrAlg">Key encryption algorithm [default=<c>rsaEncryption</c>]</param>
		/// <param name="hashAlg">Hash algorithm used in KDF [ignored - for future use]</param>
		/// <param name="advOptions">Advanced options. See <see cref="Cms.EnvDataOptions"/>.</param>
		/// <returns>Number of successful recipients or a negative <see cref="General.ErrorLookup">error code</see>.</returns>
		/// <remarks>This method is superfluous since the alternative RSA-KEM algorithm was withdrawn.
		/// Use <see cref="Cms.MakeEnvData(string,string,string,CipherAlgorithm,EnvDataOptions)"/>. 
		/// </remarks>
		public static int MakeEnvData(string outputFile, string inputFile,
			string certList, CipherAlgorithm cipherAlg, KeyEncrAlgorithm keyEncrAlg,
			HashAlgorithm hashAlg, EnvDataOptions advOptions)
		{
			int flags = (int)advOptions | (int)cipherAlg | (int)keyEncrAlg;
			/* [RSA-KEM withdrawn in v3.4]
			if (KeyEncrAlgorithm.Rsa_Kem == keyEncrAlg)
				flags |= (int)hashAlg;
			*/
			int r = CMS_MakeEnvData(outputFile, inputFile, certList, "", 0, flags);
			return r;
		}

		/// <overloads>The same as MakeEnvData except the input is from an ANSI string instead of a file</overloads>
		/// <summary>
		/// The same as Cms.MakeEnvData except the input is from an ANSI string instead of a file
		/// </summary>
		/// <param name="outputFile">Output file to be created</param>
		/// <param name="inputData">Input data text</param>
		/// <param name="certList">List of X509 certificate filename(s), separated by semi-colons</param>
		/// <param name="options">Option flags: set as zero for defaults.</param>
		/// <returns>Number of successful recipients or negative <see cref="General.ErrorLookup">error code</see></returns>
		public static int MakeEnvDataFromString(string outputFile, string inputData,
			string certList, Cms.Options options)
		{
			int flags = (int)options;
			int r = CMS_MakeEnvDataFromString(outputFile, inputData, certList, "", 0, flags);
			return r;
		}

		/// <summary>
		/// The same as Cms.MakeEnvData except the input is from an ANSI string instead of a file (alternative content encryption algorithm)
		/// </summary>
		/// <param name="outputFile">Output file to be created</param>
		/// <param name="inputData">Input data text</param>
		/// <param name="certList">List of X509 certificate filename(s), separated by semi-colons</param>
		/// <param name="cipherAlg">Content encryption algorithm [default=Triple DES]</param>
		/// <param name="advOptions">Advanced options. See <see cref="Cms.EnvDataOptions"/>.</param>
		/// <returns>Number of successful recipients or negative <see cref="General.ErrorLookup">error code</see></returns>
		public static int MakeEnvDataFromString(string outputFile, string inputData,
			string certList, CipherAlgorithm cipherAlg, EnvDataOptions advOptions)
		{
			int flags = (int)advOptions | (int)cipherAlg;
			int r = CMS_MakeEnvDataFromString(outputFile, inputData, certList, "", 0, flags);
			return r;
		}
		/// <summary>
		/// The same as Cms.MakeEnvData except the input is from an ANSI string instead of a file [superflous]
		/// </summary>
		/// <param name="outputFile">Output file to be created</param>
		/// <param name="inputData">Input data text</param>
		/// <param name="certList">List of X509 certificate filename(s), separated by semi-colons</param>
		/// <param name="cipherAlg">Content encryption algorithm [default=Triple DES]</param>
		/// <param name="keyEncrAlg">Key encryption algorithm [default=<c>rsaEncryption</c>)]</param>
		/// <param name="hashAlg">Hash algorithm used in KDF (ignored - for future use) [default=SHA-1]</param>
		/// <param name="advOptions">Advanced options. See <see cref="Cms.EnvDataOptions"/>.</param>
		/// <returns>Number of successful recipients or negative <see cref="General.ErrorLookup">error code</see></returns>
		/// <remarks>This method is superfluous since the alternative RSA-KEM algorithm was withdrawn.
		/// Use <see cref="Cms.MakeEnvDataFromString(string,string,string,CipherAlgorithm,EnvDataOptions)"/>. 
		/// </remarks>
		public static int MakeEnvDataFromString(string outputFile, string inputData,
			string certList, CipherAlgorithm cipherAlg, KeyEncrAlgorithm keyEncrAlg,
			HashAlgorithm hashAlg, EnvDataOptions advOptions)
		{
			int flags = (int)advOptions | (int)cipherAlg | (int)keyEncrAlg;
			/* [RSA-KEM withdrawn in v3.4]
			if (KeyEncrAlgorithm.Rsa_Kem == keyEncrAlg)
				flags |= (int)hashAlg;
			*/
			int r = CMS_MakeEnvDataFromString(outputFile, inputData, certList, "", 0, flags);
			return r;
		}

		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int CMS_ReadEnvData(string strFileOut, string strFileIn,
			string strX509File, string strRSAPrivateKey, int nOptions);

		/// <summary>
		/// Reads and decrypts CMS enveloped-data object using the recipient's private key.
		/// </summary>
		/// <param name="outputFile">Name of output file to be created</param>
		/// <param name="inputFile">File that contains the CMS-enveloped data</param>
		/// <param name="x509File">(optional) specifies the filename of the recipient's X.509 certificate</param>
		/// <param name="privateKey">Internal representation of private key</param>
		/// <param name="options">Option flags: set as zero for defaults.</param>
		/// <returns>Zero if successful; otherwise it returns an <see cref="General.ErrorLookup">error code</see></returns>
		public static int ReadEnvDataToFile(string outputFile, string inputFile,
			string x509File, string privateKey, Cms.Options options)
		{
			int r = CMS_ReadEnvData(outputFile, inputFile, x509File, privateKey, (int)options);
			return r;
		}

		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int CMS_ReadEnvDataToString(StringBuilder sbDataOut, int nDataOutLen, string strFileIn,
			string strX509File, string strRSAPrivateKey, int nOptions);

		/// <summary>
		/// Reads and decrypts CMS enveloped-data object using the recipient's private key
		/// </summary>
		/// <param name="inputFile">File that contains the CMS-enveloped data</param>
		/// <param name="x509File">(optional) specifies the filename of the recipient's X.509 certificate</param>
		/// <param name="privateKey">Internal representation of private key</param>
		/// <param name="options">Option flags: set as zero for defaults.</param>
		/// <returns>Message text or an empty string on error</returns>
		public static string ReadEnvDataToString(string inputFile, string x509File, string privateKey, Cms.Options options)
		{
			StringBuilder sb = new StringBuilder(0);
			int n = CMS_ReadEnvDataToString(sb, 0, inputFile, x509File, privateKey, (int)options);
			if (n <= 0) return String.Empty;
			sb = new StringBuilder(n);
			CMS_ReadEnvDataToString(sb, sb.Capacity, inputFile, x509File, privateKey, (int)options);
			return sb.ToString();
		}

		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int CMS_MakeSigData(string strFileOut, string strFileIn,
			string strCertList, string strRSAPrivateKey, int nOptions);

		/// <overloads>Creates a CMS object of type SignedData from an input data file.</overloads>
		/// <summary>
		/// Creates a CMS object of type SignedData from an input data file using user's private RSA key.
		/// </summary>
		/// <param name="outputFile">name of output file to be created</param>
		/// <param name="inputFile">name of file containing message data to be signed</param>
		/// <param name="certList">containing the filename of the signer's 
		/// certificate and (optionally) a list of other certificates 
		/// to be included in the output, separated by semi-colons(;)</param>
		/// <param name="privateKey">containing the private key data for the sender</param>
		/// <param name="options">Option flags: set as zero for defaults.</param>
		/// <returns>Zero if successful; otherwise it returns an <see cref="General.ErrorLookup">error code</see></returns>
		public static int MakeSigData(string outputFile, string inputFile,
			string certList, string privateKey, Cms.Options options)
		{
			int r = CMS_MakeSigData(outputFile, inputFile, certList, privateKey, (int)options);
			return r;
		}

		/// <summary>
		/// Creates a CMS object of type SignedData from an input data file using user's private RSA key 
		/// (advanced algorithms).
		/// </summary>
		/// <param name="outputFile">name of output file to be created</param>
		/// <param name="inputFile">name of file containing message data to be signed</param>
		/// <param name="certList">containing the filename of the signer's 
		/// certificate and (optionally) a list of other certificates 
		/// to be included in the output, separated by semi-colons(;)</param>
		/// <param name="privateKey">containing the private key data for the sender</param>
		/// <param name="hashAlg">Message digest algorithm to be used in signature [default=SHA-1]</param>
		/// <param name="advOptions">Advanced option flags. See <see cref="Cms.SigDataOptions"/>.</param>
		/// <returns>Zero if successful; otherwise it returns an <see cref="General.ErrorLookup">error code</see></returns>
		public static int MakeSigData(string outputFile, string inputFile,
			string certList, string privateKey, HashAlgorithm hashAlg, Cms.SigDataOptions advOptions)
		{
			int flags = (int)advOptions | (int)hashAlg;
			int r = CMS_MakeSigData(outputFile, inputFile, certList, privateKey, flags);
			return r;
		}

		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int CMS_MakeSigDataFromString(string strFileOut, string strDataIn,
			string strCertList, string strRSAPrivateKey, int nOptions);

		/// <overloads>Creates a CMS object of type SignedData from an input string.</overloads>
		/// <summary>
		/// Creates a CMS object of type SignedData from an input string
		/// </summary>
		/// <param name="outputFile">name of output file to be created</param>
		/// <param name="inputData">string containing message data to be signed</param>
		/// <param name="certList">containing the filename of the signer's 
		/// certificate and (optionally) a list of other certificates 
		/// to be included in the output, separated by semi-colons(;)</param>
		/// <param name="privateKey">containing the private key data for the sender</param>
		/// <param name="options">Option flags: set as zero for defaults.</param>
		/// <returns>Zero if successful; otherwise it returns an <see cref="General.ErrorLookup">error code</see></returns>
		public static int MakeSigDataFromString(string outputFile, string inputData,
			string certList, string privateKey, Cms.Options options)
		{
			int r = CMS_MakeSigDataFromString(outputFile, inputData, certList, privateKey, (int)options);
			return r;
		}

		/// <summary>
		/// Creates a CMS object of type SignedData from an input string (advanced options)
		/// </summary>
		/// <param name="outputFile">name of output file to be created</param>
		/// <param name="inputData">string containing message data to be signed</param>
		/// <param name="certList">containing the filename of the signer's 
		/// certificate and (optionally) a list of other certificates 
		/// to be included in the output, separated by semi-colons(;)</param>
		/// <param name="privateKey">containing the private key data for the sender</param>
		/// <param name="hashAlg">Message digest algorithm to be used in signature [default=SHA-1]</param>
		/// <param name="advOptions">Advanced option flags. See <see cref="Cms.SigDataOptions"/>.</param>
		/// <returns>Zero if successful; otherwise it returns an <see cref="General.ErrorLookup">error code</see></returns>
		public static int MakeSigDataFromString(string outputFile, string inputData,
			string certList, string privateKey, HashAlgorithm hashAlg, Cms.SigDataOptions advOptions)
		{
			int flags = (int)advOptions | (int)hashAlg;
			int r = CMS_MakeSigDataFromString(outputFile, inputData, certList, privateKey, flags);
			return r;
		}

		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int CMS_MakeSigDataFromSigValue(string strFileOut, byte[] abSigValue, int nSigLen,
			byte[] abData, int nDataLen, string strCertList, int nOptions);

		/// <overloads>Creates a CMS object of type SignedData using a pre-computed signature.</overloads>
		/// <summary>
		/// Creates a CMS object of type SignedData using a pre-computed signature
		/// </summary>
		/// <param name="outputFile">name of output file to be created</param>
		/// <param name="sigValue">signature value</param>
		/// <param name="contentData">string containing content data that has been signed</param>
		/// <param name="certList">containing the filename of the signer's 
		/// certificate and (optionally) a list of other certificates 
		/// to be included in the output, separated by semi-colons(;)</param>
		/// <param name="options">Option flags: set as zero for defaults.</param>
		/// <returns>Zero if successful; otherwise it returns an <see cref="General.ErrorLookup">error code</see></returns>
		public static int MakeSigDataFromSigValue(string outputFile, byte[] sigValue,
			byte[] contentData, string certList, Cms.Options options)
		{
			int r = CMS_MakeSigDataFromSigValue(outputFile, sigValue, sigValue.Length, contentData, contentData.Length, certList, (int)options);
			return r;
		}

		/// <summary>
		/// Creates a CMS object of type SignedData using a pre-computed signature (advanced algorithms).
		/// </summary>
		/// <param name="outputFile">name of output file to be created</param>
		/// <param name="sigValue">signature value</param>
		/// <param name="contentData">string containing content data that has been signed</param>
		/// <param name="certList">containing the filename of the signer's 
		/// certificate and (optionally) a list of other certificates 
		/// to be included in the output, separated by semi-colons(;)</param>
		/// <param name="hashAlg">Message digest algorithm to be used in signature [default=SHA-1]</param>
		/// <param name="advOptions">Advanced option flags. See <see cref="Cms.SigDataOptions"/>.</param>
		/// <returns>Zero if successful; otherwise it returns an <see cref="General.ErrorLookup">error code</see></returns>
		public static int MakeSigDataFromSigValue(string outputFile, byte[] sigValue,
			byte[] contentData, string certList, HashAlgorithm hashAlg, Cms.SigDataOptions advOptions)
		{
			int flags = (int)advOptions | (int)hashAlg;
			int r = CMS_MakeSigDataFromSigValue(outputFile, sigValue, sigValue.Length, contentData, contentData.Length, certList, flags);
			return r;
		}

		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int CMS_MakeDetachedSig(string strFileOut, string strHexDigest,
			string strCertList, string strRSAPrivateKey, int nOptions);

		/// <overloads>Creates a "detached signature" CMS signed-data object file.</overloads>
		/// <summary>
		/// Creates a "detached signature" CMS signed-data object file
		/// from a <b>message digest</b> of the content
		/// </summary>
		/// <param name="outputFile">name of output file to be created</param>
		/// <param name="hexDigest">string containing message digest in hex format</param>
		/// <param name="certList">containing the filename of the signer's 
		/// certificate and (optionally) a list of other certificates 
		/// to be included in the output, separated by semi-colons(;)</param>
		/// <param name="privateKey">containing the private key data for the sender</param>
		/// <param name="options">Option flags: set as zero for defaults.</param>
		/// <returns>Zero if successful; otherwise it returns an <see cref="General.ErrorLookup">error code</see></returns>
		public static int MakeDetachedSig(string outputFile, string hexDigest,
			string certList, string privateKey, Cms.Options options)
		{
			int r = CMS_MakeDetachedSig(outputFile, hexDigest, certList, privateKey, (int)options);
			return r;
		}

		/// <summary>
		/// Creates a "detached signature" CMS signed-data object file
		/// from a <b>message digest</b> of the content (advanced algorithms).
		/// </summary>
		/// <param name="outputFile">name of output file to be created</param>
		/// <param name="hexDigest">string containing message digest in hex format</param>
		/// <param name="certList">containing the filename of the signer's 
		/// certificate and (optionally) a list of other certificates 
		/// to be included in the output, separated by semi-colons(;)</param>
		/// <param name="privateKey">containing the private key data for the sender</param>
		/// <param name="hashAlg">Message digest algorithm to be used in signature [default=SHA-1]</param>
		/// <param name="advOptions">Advanced option flags. See <see cref="Cms.SigDataOptions"/>.</param>
		/// <returns>Zero if successful; otherwise it returns an <see cref="General.ErrorLookup">error code</see></returns>
		public static int MakeDetachedSig(string outputFile, string hexDigest,
			string certList, string privateKey, HashAlgorithm hashAlg, Cms.SigDataOptions advOptions)
		{
			int flags = (int)advOptions | (int)hashAlg;
			int r = CMS_MakeDetachedSig(outputFile, hexDigest, certList, privateKey, flags);
			return r;
		}

		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int CMS_ReadSigData(string strFileOut, string strFileIn,
			int nOptions);

		/// <summary>
		/// Reads the content from a CMS signed-data object file
		/// </summary>
		/// <param name="outputFile">file to receive content</param>
		/// <param name="inputFile">file containing CMS signed-data object</param>
		/// <returns>If successful, the return value is a positive number indicating the number of bytes in the content; 
		/// otherwise it returns a negative <see cref="General.ErrorLookup">error code</see>.</returns>
		public static int ReadSigDataToFile(string outputFile, string inputFile)
		{
			int r = CMS_ReadSigData(outputFile, inputFile, 0);
			return r;
		}

		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int CMS_ReadSigDataToString(StringBuilder sbDataOut, int nDataOutLen,
			string strFileIn, int nOptions);

		/// <summary>
		/// Reads the content from a CMS signed-data object file directly into a string
		/// </summary>
		/// <param name="inputFile">file containing CMS signed-data object</param>
		/// <returns>String containing the content or an empty string if error</returns>
		public static string ReadSigDataToString(string inputFile)
		{
			StringBuilder sb = new StringBuilder(0);
			int n = CMS_ReadSigDataToString(sb, 0, inputFile, 0);
			if (n <= 0) return String.Empty;
			sb = new StringBuilder(n);
			CMS_ReadSigDataToString(sb, sb.Capacity, inputFile, 0);
			return sb.ToString();
		}

		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int CMS_GetSigDataDigest(StringBuilder sbHexDigestOut, int nDigestLen,
			string strFileIn, string strX509File, int nOptions);

		/// <summary>
		/// Extracts the message digest from a signed-data CMS object file 
		/// and verifies the signature
		/// </summary>
		/// <param name="inputFile">file containing CMS signed-data object</param>
		/// <param name="certFile">an (optional) X.509 certificate file to be used to identify the signer</param>
		/// <returns>Hash value in hex format or an empty string if error</returns>
		/// <remarks>If no certificate is given, it will use the first valid SignerInfo and certificate pair it finds in the SignedData.</remarks>
		public static string GetSigDataDigest(string inputFile, string certFile)
		{
			// We know the max length of a hash digest
			StringBuilder sb = new StringBuilder((int)HashLen.PKI_MAX_HASH_CHARS);
			int n = CMS_GetSigDataDigest(sb, sb.Capacity, inputFile, certFile, 0);
			// Return value is ID of hash algorithm or -ve error code
			if (n < 0) return String.Empty;
			return sb.ToString();
		}

		/// <summary>
		/// Finds ID of message digest hash algorithm used to make signature.
		/// </summary>
		/// <param name="inputFile">file containing CMS signed-data object</param>
		/// <param name="certFile">an (optional) X.509 certificate file to be used to identify the signer</param>
		/// <returns>0=SHA-1, 1=MD5, 2=MD2, 3=SHA-256, 4=SHA-384, 5=SHA-512, 6=SHA-224; or a negative <see cref="General.ErrorLookup">error code</see></returns>
		/// <remarks>This method returns an integer ID number. 
		/// Alternatively, use <c>Cms.QuerySigData(inputFile, "digestAlgorithm")</c> 
		/// to get the name directly as a string, e.g. <c>"sha1"</c>.
		/// See <see cref="QuerySigData(string, string)"/></remarks>
		public static int GetSigHashAlgorithm(string inputFile, string certFile)
		{
			// We know the max length of a hash digest
			StringBuilder sb = new StringBuilder((int)HashLen.PKI_MAX_HASH_CHARS);
			int n = CMS_GetSigDataDigest(sb, sb.Capacity, inputFile, certFile, 0);
			// Return value is ID of hash algorithm or -ve error code
			return n;
		}

		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int CMS_VerifySigData(string strFileIn, string strCertFile,
			string strHexDigest, int nOptions);

		/// <overloads>Verifies the signature and content of a signed-data CMS object.</overloads>
		/// <summary>
		/// Verifies the signature and content of a signed-data CMS object file.
		/// </summary>
		/// <param name="inputFile">file containing CMS signed-data object</param>
		/// <returns>Zero if successfully verified; otherwise it returns a non-zero <see cref="General.ErrorLookup">error code</see></returns>
		public static int VerifySigData(string inputFile)
		{
			int r = CMS_VerifySigData(inputFile, "", "", 0);
			return r;
		}

		/// <summary>
		/// Verifies the signature and content of a signed-data CMS object file with specified certificate.
		/// </summary>
		/// <param name="inputFile">file containing CMS signed-data object</param>
		/// <param name="certFile">X.509 certificate file of the signer</param>
		/// <returns>Zero if successfully verified; otherwise it returns a non-zero <see cref="General.ErrorLookup">error code</see></returns>
		public static int VerifySigData(string inputFile, string certFile)
		{
			int r = CMS_VerifySigData(inputFile, certFile, "", 0);
			return r;
		}

		/// <summary>
		/// Verifies the signature and content of a signed-data CMS object file (advanced options)
		/// </summary>
		/// <param name="inputFile">file containing CMS signed-data object</param>
		/// <param name="certFile">an (optional) X.509 certificate file of the signer</param>
		/// <param name="hexDigest">(optional) digest of eContent to be verified (use for "detached-signature" form)</param>
		/// <param name="advOptions">Use for <c>BigFile</c> option</param>
		/// <returns>Zero if successfully verified; otherwise it returns a non-zero <see cref="General.ErrorLookup">error code</see></returns>
		public static int VerifySigData(string inputFile,
			string certFile, string hexDigest, Cms.SigDataOptions advOptions)
		{
			int r = CMS_VerifySigData(inputFile, certFile, hexDigest, (int)advOptions);
			return r;
		}

		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int CMS_MakeComprData(string szFileOut, string szFileIn, int nOptions);

		/// <summary>
		/// Creates a new CMS compressed-data file (.p7z) from an existing input file.
		/// </summary>
		/// <param name="outputFile">Output file to be created</param>
		/// <param name="inputFile">Input data file</param>
		/// <returns>Zero if successful; otherwise it returns a non-zero <see cref="General.ErrorLookup">error code</see></returns>    
		public static int MakeComprData(string outputFile, string inputFile)
		{
			int r = CMS_MakeComprData(outputFile, inputFile, 0);
			return r;
		}

		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int CMS_ReadComprData(string szFileOut, string szFileIn, int nOptions);

		/// <summary>
		/// Read and extract the decompressed contents of a CMS compressed-data file.
		/// </summary>
		/// <param name="outputFile">Output file to be created</param>
		/// <param name="inputFile">Input data file</param>
		/// <param name="opts">Options [default=inflate contents]</param>
		/// <returns>If successful the return value is the number of bytes in the output file; otherwise it returns a non-zero <see cref="General.ErrorLookup">error code</see></returns>    
		public static int ReadComprData(string outputFile, string inputFile, ComprDataOptions opts)
		{
			int r = CMS_ReadComprData(outputFile, inputFile, (int)opts);
			return r;
		}

		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int CMS_QuerySigData(StringBuilder sbDataOut, int nDataOutLen,
			string strFileIn, string strQuery, int nOptions);

		/// <summary>
		/// Queries a CMS signed-data object for selected information.
		/// </summary>
		/// <param name="inputFile">file containing CMS signed-data object</param>
		/// <param name="query">Query string (case insensitive)</param>
		/// <returns>String containing the result or an empty string if not found or error.</returns>
		/// <remarks>
		/// <para>Valid queries are:</para>
		/// <list type="table">
		/// <item>
		/// <term><c>"version"</c></term>
		/// <description>signedData version (sdVer) value, e.g. <c>"1"</c>.</description>
		/// </item>
		/// <item>
		/// <term><c>"eContentType"</c></term>
		/// <description>ContentType of the EncapsulatedContentInfo, e.g. <c>"data"</c>.</description>
		/// </item>
		/// <item>
		/// <term><c>"HASeContent"</c></term>
		/// <description>"1" if eContent is present; "0" if not.</description>
		/// </item>
		/// <item>
		/// <term><c>"CountOfCertificates"</c></term>
		/// <description>Number of certificates included in the data. </description>
		/// </item>
		/// <item>
		/// <term><c>"CountOfSignerInfos"</c></term>
		/// <description>Number of SignerInfos included in the data.</description>
		/// </item>
		/// <item>
		/// <term><c>"signerInfoVersion"</c></term>
		/// <description>signerInfo version (siVer) value.</description>
		/// </item>
		/// <item>
		/// <term><c>"digestAlgorithm"</c></term>
		/// <description>digestAlgorithm, e.g. <c>"sha1"</c>.</description>
		/// </item>
		/// <item>
		/// <term><c>"SigAlgorithm"</c></term>
		/// <description>SigAlgorithm, e.g. <c>"rsaEncryption"</c>.</description>
		/// </item>
		/// <item>
		/// <term><c>"HASsignedAttributes"</c></term>
		/// <description>"1" if signedAttributes (authenticatedAttributes) are present; "0" if not.</description>
		/// </item>
		/// <item>
		/// <term><c>"signingTime"</c></term>
		/// <description>Date on which the certificate validity period begins in format 
		/// <c>"2005-12-31 23:30:59"</c>
		/// </description>
		/// </item>
		/// <item>
		/// <term><c>"messageDigest"</c></term>
		/// <description>messageDigest attribute in hexadecimal format, if present</description>
		/// </item>
		/// </list>
		///</remarks>
		public static string QuerySigData(string inputFile, string query)
		{
			int n;
			StringBuilder sb = new StringBuilder(0);

			// CMS_QuerySigData either returns an integer result directly or sets the string
			n = CMS_QuerySigData(null, 0, inputFile, query, (int)myQuery.PKI_QUERY_GETTYPE);
			if (n == (int)myQuery.PKI_QUERY_STRING)
			{
				n = CMS_QuerySigData(sb, 0, inputFile, query, 0);
				if (n <= 0) return String.Empty;
				sb = new StringBuilder(n);
				CMS_QuerySigData(sb, sb.Capacity, inputFile, query, 0);
			}
			else
			{
				n = CMS_QuerySigData(sb, 0, inputFile, query, 0);
			}
			if (sb.Length == 0)
			{	// Result is an integer returned in n, so set our return value as a string
				sb.Append(n);
			}
			return sb.ToString();
		}

		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int CMS_QueryEnvData(StringBuilder sbDataOut, int nDataOutLen,
			string strFileIn, string strQuery, int nOptions);

		/// <summary>
		/// Queries a CMS enveloped-data object file for selected information.
		/// </summary>
		/// <param name="inputFile">file containing CMS enveloped-data object</param>
		/// <param name="query">Query string (case insensitive)</param>
		/// <returns>String containing the result or an empty string if not found or error.</returns>
		/// <remarks>
		/// <para>Valid queries are:</para>
		/// <list type="table">
		/// <item>
		/// <term><c>"version"</c></term>
		/// <description>envelopedData CMSVersion value, e.g. <c>"0"</c>.</description>
		/// </item>
		/// <item>
		/// <term><c>"countOfRecipientInfos"</c></term>
		/// <description>Number of RecipientInfos included in the data.</description>
		/// </item>
		/// <item>
		/// <term><c>"contentEncryptionAlgorithm"</c></term>
		/// <description>contentEncryptionAlgorithm, e.g. <c>"des-EDE3-CBC"</c>.</description>
		/// </item>
		/// <item>
		/// <term><c>"sizeofEncryptedContent"</c></term>
		/// <description>Size (in bytes) of the EncryptedContent.</description>
		/// </item>
		/// <item>
		/// <term><c>"recipientInfoVersion"</c></term>
		/// <description>recipientInfo version (riVer) value.</description>
		/// </item>
		/// <item>
		/// <term><c>"keyEncryptionAlgorithm"</c></term>
		/// <description>keyEncryptionAlgorithm, e.g. <c>"rsaEncryption"</c>.</description>
		/// </item>
		/// <item>
		/// <term><c>"keyEncryptionFlags"</c></term>
		/// <description>Bit flags used for the key encryption algorithm.</description>
		/// </item>
		/// <item>
		/// <term><c>"sizeofEncryptedKey"</c></term>
		/// <description>Size (in bytes) of the EncryptedKey.</description>
		/// </item>
		/// <item>
		/// <term><c>"recipientIssuerName"</c></term>
		/// <description>Distinguished Name of recipient's certificate issuer.</description>
		/// </item>
		/// <item>
		/// <term><c>"recipientSerialNumber"</c></term>
		/// <description>serialNumber of recipient's certificate in hex format</description>
		/// </item>
		/// </list>
		///</remarks>
		public static string QueryEnvData(string inputFile, string query)
		{
			int n;
			StringBuilder sb = new StringBuilder(0);

			// CMS_QueryEnvData either returns an integer result directly or sets the string
			n = CMS_QueryEnvData(null, 0, inputFile, query, (int)myQuery.PKI_QUERY_GETTYPE);
			if (n == (int)myQuery.PKI_QUERY_STRING)
			{
				n = CMS_QueryEnvData(sb, 0, inputFile, query, 0);
				if (n <= 0) return String.Empty;
				sb = new StringBuilder(n);
				CMS_QueryEnvData(sb, sb.Capacity, inputFile, query, 0);
			}
			else
			{
				n = CMS_QueryEnvData(sb, 0, inputFile, query, 0);
			}
			if (sb.Length == 0)
			{	// Result is an integer returned in n, so set our return value as a string
				sb.Append(n);
			}
			return sb.ToString();
		}
	}

	/// <summary>
	/// RSA Encryption and Public Key Functions
	/// </summary>
	public class Rsa
	{
		private Rsa()
		{}	// Static methods only, so hide constructor.

		private const int KEYGEN_INDICATE = 0x1000000;  /* CAUTION: changed from 0x10 in v3.3 */
		private const int PKI_KEY_FORMAT_PEM = 0x10000;
		private const int PKI_KEY_FORMAT_SSL = 0x20000;
		private const int PKI_XML_RSAKEYVALUE  = 0x0001;
		private const int PKI_XML_EXCLPRIVATE  = 0x0010;
		private const int PKI_XML_HEXBINARY   =  0x0100;
		private const int PKI_XML_REQPRIVATE = 0x0020;
		private const int PKI_PBE_PBES2 =  0x1000;
		// NB The next 3 have changed in [v11.0] (added 0x8000000)
		private const int PKI_PBE_MD5_DES = 0x8000001;
		private const int PKI_PBE_MD2_DES = 0x8000002;
		private const int PKI_PBE_SHA_DES = 0x8000003;
		private const int PKI_PBE_PBKDF2_DESEDE3 = 0x1010;
		private const int PKI_PBE_PBKDF2_AES128  = 0x1020;
		private const int PKI_PBE_PBKDF2_AES192  = 0x1030;
		private const int PKI_PBE_PBKDF2_AES256  = 0x1040;
		/*
		private const int PKI_PBE_SCRYPT_AES128  = 0x1820;
		private const int PKI_PBE_SCRYPT_AES256  = 0x1840;
		*/

		/// <summary>
		/// Password-based encryption scheme to be used to encrypt the private key file
		/// </summary>
		public enum PbeOptions
		{
			/// <summary>
			/// Default option (pbeWithSHAAnd3-KeyTripleDES-CBC)
			/// </summary>
			Default = 0,
			/// <summary>
			/// pbeWithSHAAnd3-KeyTripleDES-CBC from PKCS#12
			/// </summary>
			PbeWithSHAAnd_KeyTripleDES_CBC = 0,
			/// <summary>
			/// "pkcs5PBES2" with key derivation function "pkcs5PBKDF2" and encryption scheme "des-EDE3-CBC"
			/// </summary>
			Pbe_Pbkdf2_des_EDE3_CBC = PKI_PBE_PBKDF2_DESEDE3,
			/// <summary>
			/// "pkcs5PBES2" with key derivation function "pkcs5PBKDF2" and encryption scheme "aes128-CBC"
			/// </summary>
			Pbe_Pbkdf2_aes128_CBC = PKI_PBE_PBKDF2_AES128,
			/// <summary>
			/// "pkcs5PBES2" with key derivation function "pkcs5PBKDF2" and encryption scheme "aes192-CBC"
			/// </summary>
			Pbe_Pbkdf2_aes192_CBC = PKI_PBE_PBKDF2_AES192,
			/// <summary>
			/// "pkcs5PBES2" with key derivation function "pkcs5PBKDF2" and encryption scheme "aes256-CBC"
			/// </summary>
			Pbe_Pbkdf2_aes256_CBC = PKI_PBE_PBKDF2_AES256,

			/* [later...]
			/// <summary>
			/// "pkcs5PBES2" with key derivation function "scrypt" and encryption scheme "aes128-CBC"
			/// </summary>
			Pbe_Scrypt_aes128_CBC = PKI_PBE_SCRYPT_AES128,
			/// <summary>
			/// "pkcs5PBES2" with key derivation function "scrypt" and encryption scheme "aes256-CBC"
			/// </summary>
			Pbe_Scrypt_aes256_CBC = PKI_PBE_SCRYPT_AES256,
			*/

			// LEGACY STUFF...
			/// <summary>
			/// pbeWithMD5AndDES-CBC [legacy, not recommended for new implementations]
			/// </summary>
			PbeWithMD5AndDES_CBC = PKI_PBE_MD5_DES,
			/// <summary>
			/// pbeWithMD2AndDES-CBC [legacy, not recommended for new implementations]
			/// </summary>
			PbeWithMD2AndDES_CBC = PKI_PBE_MD2_DES,
			/// <summary>
			/// pbeWithSHA1AndDES-CBC [legacy, not recommended for new implementations]
			/// </summary>
			PbeWithSHA1AndDES_CBC = PKI_PBE_SHA_DES,
			/// <summary>
			/// "pkcs5PBES2" with "pkcs5PBKDF2" and "des-EDE3-CBC" 
			/// [Synonym retained for backwards compatibility]
			/// </summary>
			Pkcs5PBES2_des_EDE3_CBC = PKI_PBE_PBKDF2_DESEDE3,
		}
		
		/// <summary>
		/// Choices for public exponent (e)
		/// </summary>
		/// <remarks>Fermat Number F(x) = 2^(2^x) + 1. F0 to F4 are prime.</remarks>
		public enum PublicExponent
		{
			/// <summary>
			/// Set exponent equal to 3 (F0)
			/// </summary>
			Exp_EQ_3 = 0,
			/// <summary>
			/// Set exponent equal to 5 (F1)
			/// </summary>
			Exp_EQ_5 = 1,
			/// <summary>
			/// Set exponent equal to 17 (F2)
			/// </summary>
			Exp_EQ_17 = 2,
			/// <summary>
			/// Set exponent equal to 257 (F3)
			/// </summary>
			Exp_EQ_257 = 3,
			/// <summary>
			/// Set exponent equal to 65537 (F4)
			/// </summary>
			Exp_EQ_65537 = 4,
		}

		/// <summary>
		/// Format for saved RSA key
		/// </summary>
		public enum Format
		{
			/// <summary>
			/// Default = Binary
			/// </summary>
			Default = 0,
			/// <summary>
			/// Binary DER-encoded
			/// </summary>
			Binary = 0,
			/// <summary>
			/// PEM Format
			/// </summary>
			PEM = PKI_KEY_FORMAT_PEM,
			/// <summary>
			/// PEM format compatible with OpenSSL
			/// </summary>
			SSL = PKI_KEY_FORMAT_SSL,
		}

		// Number of Rabin-Miller primality tests to perform
		// - this gives a probablity of 2^-128 of a wrong answer.
		private const int PRIME_TESTS = 64;

		/* RSA KEY FUNCTIONS */
		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int RSA_MakeKeys(string strPubKeyFile, string strPVKFile,
			int nBits, int nExpFermat, int nCount, int nTests,
			string strPassword, byte[] lpSeed, int nSeedLen, int nOptions);

		/// <summary>
		/// Generate an RSA public/private key pair
		/// </summary>
		/// <param name="publicKeyFile">Output filename for public key</param>
		/// <param name="privateKeyFile">Output filename for (encrypted) private key</param>
		/// <param name="bits">Required key modulus size in bits (min 96)</param>
		/// <param name="exponent">Exponent (Fermat Prime)</param>
		/// <param name="iterCount">Iteration count for encrypted private key</param>
		/// <param name="password">Password string for encrypted private key</param>
		/// <param name="cryptOption">Option to specify encryption algorithm for private key</param>
		/// <param name="showProgress">Indicate progress in console</param>
		/// <returns>Zero if successful or non-zero <see cref="General.ErrorLookup">error code</see></returns>
		/// <overloads>Generate an RSA public/private key pair</overloads>
		public static int MakeKeys(string publicKeyFile, string privateKeyFile, 
			int bits, PublicExponent exponent, int iterCount,
			string password, Rsa.PbeOptions cryptOption, bool showProgress)
		{
			int flags = (showProgress ? KEYGEN_INDICATE : 0) | (int)cryptOption;
			int r = RSA_MakeKeys(publicKeyFile, privateKeyFile, bits, (int)exponent, 
				PRIME_TESTS, iterCount, password, null, 0, flags);
			return r;
		}
		/// <summary>
		/// Generate an RSA public/private key pair, adding user-supplied entropy
		/// </summary>
		/// <param name="publicKeyFile">Output filename for public key</param>
		/// <param name="privateKeyFile">Output filename for (encrypted) private key</param>
		/// <param name="bits">Required key modulus size in bits (min 96)</param>
		/// <param name="exponent">Exponent (Fermat Prime)</param>
		/// <param name="iterCount">Iteration count for encrypted private key</param>
		/// <param name="password">Password string for encrypted private key</param>
		/// <param name="cryptOption">Option to specify encryption algorithm for private key</param>
		/// <param name="showProgress">Indicate progress in console</param>
		/// <param name="seedBytes">User-supplied-entropy in byte format</param>
		/// <returns>Zero if successful or non-zero <see cref="General.ErrorLookup">error code</see></returns>
		public static int MakeKeys(string publicKeyFile, string privateKeyFile, 
			int bits, PublicExponent exponent, int iterCount,
			string password, Rsa.PbeOptions cryptOption, bool showProgress,
			byte[] seedBytes)
		{
			int flags = (showProgress ? KEYGEN_INDICATE : 0) | (int)cryptOption;
			int r = RSA_MakeKeys(publicKeyFile, privateKeyFile, bits, (int)exponent, 
				PRIME_TESTS, iterCount, password, seedBytes, seedBytes.Length, flags);
			return r;
		}
		
		/// <summary>
		/// Generate an RSA public/private key pair with extended options for encrypting private key.
		/// </summary>
		/// <param name="publicKeyFile">Output filename for public key</param>
		/// <param name="privateKeyFile">Output filename for (encrypted) private key</param>
		/// <param name="bits">Required key modulus size in bits (min 96)</param>
		/// <param name="exponent">Exponent (Fermat Prime)</param>
		/// <param name="iterCount">Iteration count for encrypted private key</param>
		/// <param name="password">Password string for encrypted private key</param>
		/// <param name="cipherAlg">Block cipher to use for encryption scheme [default = des-ede3-cbc]</param>
		/// <param name="hashAlg">Hash function to use in PRF HMAC algorithm [default = hmacWithSHA1]</param>
		/// <param name="fileFormat">Format to save file [default = DER binary]</param>
		/// <param name="showProgress">Indicate progress in console</param>
		/// <returns>Zero if successful or non-zero <see cref="General.ErrorLookup">error code</see></returns>
		/// <remarks>The private key is saved in encrypted PKCS#8 format using
		/// the PBES2 encryption scheme from PKCS#5 with key derivation function PBKDF2.
		/// </remarks>
		public static int MakeKeys(string publicKeyFile, string privateKeyFile, 
			int bits, PublicExponent exponent, int iterCount, string password, 
			CipherAlgorithm cipherAlg, HashAlgorithm hashAlg, Rsa.Format fileFormat,
			bool showProgress)
		{
			// This version always uses PBES2
			int flags = PKI_PBE_PBES2 | (int)cipherAlg | (int)hashAlg | (int)fileFormat;
			if (showProgress) flags |= KEYGEN_INDICATE;
			int r = RSA_MakeKeys(publicKeyFile, privateKeyFile, bits, (int)exponent, 
				PRIME_TESTS, iterCount, password, null, 0, flags);
			return r;
		}

		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int RSA_ReadAnyPrivateKey(StringBuilder szOutput, int nOutChars, string szKeyFile, string szPassword, int nOptions);

		/// <summary>
		/// Read from a file or string containing a private key into an "internal" private key string
		/// </summary>
		/// <param name="privateKeyFile">Name of private key file or a PEM String containing the key</param>
		/// <param name="password">Password for private key, if encrypted</param>
		/// <returns>StringBuilder containing an internal representation of the
		/// private key; or an empty StringBuilder if error </returns>
		/// <remarks>This returns a StringBuilder, not a string, to allow secure wiping. 
		/// Use sb.ToString() to obtain a string.
		/// </remarks>
		public static StringBuilder ReadPrivateKey(string privateKeyFile, string password)
		{
			StringBuilder sb = new StringBuilder(0);
			int n = RSA_ReadAnyPrivateKey(sb, 0, privateKeyFile, password, 0);
			if (n <= 0) return sb;
			sb = new StringBuilder(n);
			RSA_ReadAnyPrivateKey(sb, sb.Capacity, privateKeyFile, password, 0);
			return sb;
		}

		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int RSA_ReadAnyPublicKey(StringBuilder szOutput, int nOutChars, string szKeyFile, int nOptions);
		
		/// <summary>
		/// Read from a file or string containing a public key into an "internal" public key string
		/// </summary>
		/// <param name="certOrPublicKeyFile">Name of X.509 certificate or public key file or a PEM String containing the key</param>
		/// <returns>StringBuilder containing an internal representation of the
		/// public key; or an empty StringBuilder if error </returns>
		/// <remarks>This returns a StringBuilder, not a string. 
		/// Use sb.ToString() to obtain a string.
		/// </remarks>
		public static StringBuilder ReadPublicKey(string certOrPublicKeyFile)
		{
			StringBuilder sb = new StringBuilder(0);
			int n = RSA_ReadAnyPublicKey(sb, 0, certOrPublicKeyFile, 0);
			if (n <= 0) return sb;
			sb = new StringBuilder(n);
			RSA_ReadAnyPublicKey(sb, sb.Capacity, certOrPublicKeyFile, 0);
			return sb;
		}

		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int RSA_ReadEncPrivateKey(StringBuilder sbOutput, int nOutputLen, string strPVKFile,
			string strPassword, int nOptions);
		/// <summary>
		/// Read encrypted private key file into internal string format
		/// </summary>
		/// <param name="privateKeyFile">filename of a binary BER-encoded encrypted private key info file</param>
		/// <param name="password">password for key file</param>
		/// <returns>StringBuilder containing an internal representation of the
		/// private key; or an empty StringBuilder if error </returns>
		/// <remarks>This returns a StringBuilder, not a string. 
		/// Use sb.ToString() to obtain a string. 
		/// </remarks>
		[Obsolete("Use Rsa.ReadPrivateKey() instead", false)]
		public static StringBuilder ReadEncPrivateKey(string privateKeyFile, string password)
		{
			StringBuilder sb = new StringBuilder(0);
			int n = RSA_ReadEncPrivateKey(sb, 0, privateKeyFile, password, 0);
			if (n <= 0) return sb;
			sb = new StringBuilder(n);
			RSA_ReadEncPrivateKey(sb, sb.Capacity, privateKeyFile, password, 0);
			return sb;
		}
		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int RSA_ReadPrivateKeyInfo(StringBuilder sbOutput, int nOutputLen, string strKeyFile, int nOptions);
		/// <summary>
		/// Read from an (unencrypted) PKCS-8 private key info file into a private key string
		/// </summary>
		/// <param name="prikeyinfoFile">Name of file</param>
		/// <returns>StringBuilder containing an internal representation of the
		/// private key; or an empty StringBuilder if error </returns>
		/// <remarks>This returns a StringBuilder, not a string. 
		/// Use sb.ToString() to obtain a string. 
		/// </remarks>
		[Obsolete("Use Rsa.ReadPrivateKey() instead", false)]
		public static StringBuilder ReadPrivateKeyInfo(string prikeyinfoFile)
		{
			StringBuilder sb = new StringBuilder(0);
			int n = RSA_ReadPrivateKeyInfo(sb, 0, prikeyinfoFile, 0);
			if (n <= 0) return sb;
			sb = new StringBuilder(n);
			RSA_ReadPrivateKeyInfo(sb, sb.Capacity, prikeyinfoFile, 0);
			return sb;
		}
		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int RSA_GetPrivateKeyFromPFX(string strOutputFile, string strPFXFile,
			int nOptions);
		/// <summary>
		/// Extract an encrypted private key from a PKCS-12 PKCS8ShroudedKeyBag, 
		/// saving the output directly as a new file
		/// </summary>
		/// <param name="outputFile">Name of new file to create</param>
		/// <param name="pfxFile">PKCS-12 filename</param>
		/// <returns>If successful, it returns the number of bytes written to the output file; 
		/// otherwise it returns a negative <see cref="General.ErrorLookup">error code</see></returns>
		public static int GetPrivateKeyFromPFX(string outputFile, string pfxFile)
		{
			return RSA_GetPrivateKeyFromPFX(outputFile, pfxFile, 0);
		}

		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int RSA_ReadPrivateKeyFromPFX(StringBuilder sbOutput, int nOutputLen, string strPfxFile,
			string strPassword, int nOptions);
			  
		/// <summary>
		/// Read a private key directly from an encrypted PFX/PKCS-12 file into an "internal" private key string.
		/// </summary>
		/// <param name="pfxFile">PKCS-12 filename</param>
		/// <param name="password">Password for PFX file</param>
		/// <returns>StringBuilder containing an internal representation of the
		/// private key; or an empty StringBuilder if error</returns>
		/// <remarks>This returns a StringBuilder, not a string. 
		/// Use sb.ToString() to obtain a string. 
		/// </remarks>
		[Obsolete("Use Rsa.ReadPrivateKey() instead", false)]
		public static StringBuilder ReadPrivateKeyFromPFX(string pfxFile, string password)
		{
			StringBuilder sb = new StringBuilder(0);
			int n = RSA_ReadPrivateKeyFromPFX(sb, 0, pfxFile, password, 0);
			if (n <= 0) return sb;
			sb = new StringBuilder(n);
			RSA_ReadPrivateKeyFromPFX(sb, sb.Capacity, pfxFile, password, 0);
			return sb;
		}

		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int RSA_PublicKeyFromPrivate(StringBuilder sbOutput, int nOutputLen, string strKeyString,
			int nOptions);

		/// <summary>
		/// Convert an internal private key string into a public one.
		/// </summary>
		/// <param name="sbKeyString">StringBuilder containing private key in "internal" format</param>
		/// <returns>StringBuilder containing an internal representation of the
		/// public key; or an empty StringBuilder if error</returns>
		/// <remarks>This returns a StringBuilder, not a string. 
		/// Use sb.ToString() to obtain a string. 
		/// </remarks>
		public static StringBuilder PublicKeyFromPrivate(StringBuilder sbKeyString)
		{
			StringBuilder sb = new StringBuilder(0);
			int n = RSA_PublicKeyFromPrivate(sb, 0, sbKeyString.ToString(), 0);
			if (n <= 0) return sb;
			sb = new StringBuilder(n);
			RSA_PublicKeyFromPrivate(sb, sb.Capacity, sbKeyString.ToString(), 0);
			return sb;
		}

		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int RSA_GetPublicKeyFromCert(StringBuilder sbOutput, int nOutputLen, string strCertFile, int flags);
		/// <summary>
		/// Read public key from X.509 certificate into internal string format
		/// </summary>
		/// <param name="certFile">Filename of certificate file (or its base64 representation)</param>
		/// <returns>StringBuilder containing an internal representation of the
		/// public key; or an empty StringBuilder if error </returns>
		/// <remarks>This returns a StringBuilder, not a string. 
		/// Use sb.ToString() to obtain a string. 
		/// </remarks>
		[Obsolete("Use Rsa.ReadPublicKey() instead", false)]
		public static StringBuilder GetPublicKeyFromCert(string certFile)
		{
			StringBuilder sb = new StringBuilder(0);
			int n = RSA_GetPublicKeyFromCert(sb, 0, certFile, 0);
			if (n <= 0) return sb;
			sb = new StringBuilder(n);
			RSA_GetPublicKeyFromCert(sb, sb.Capacity, certFile, 0);
			return sb;
		}

		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int RSA_SavePublicKey(string strFileOut, string strKeyString, int nOptions);

		/// <summary>
		/// Save a public key string to PKCS-1 public key file
		/// </summary>
		/// <param name="outputFile">Name of file to create</param>
		/// <param name="publicKey">Public key in internal format</param>
		/// <param name="format">File format</param>
		/// <returns>If successful, the return value is zero; otherwise it returns a nonzero <see cref="General.ErrorLookup">error code</see></returns>
		public static int SavePublicKey(string outputFile, string publicKey, Rsa.Format format)
		{
			return RSA_SavePublicKey(outputFile, publicKey, (int)format);
		}

		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int RSA_SavePrivateKeyInfo(string strFileOut, string strKeyString, int nOptions);

		/// <summary>
		/// Save a private key string to an (unencrypted) PKCS-8 private key info file
		/// </summary>
		/// <param name="outputFile">Name of file to create</param>
		/// <param name="privateKey">Private key in internal format</param>
		/// <param name="format">File format</param>
		/// <returns>If successful, the return value is zero; otherwise it returns a nonzero <see cref="General.ErrorLookup">error code</see></returns>
		/// <remarks>Do <b>not</b> use for a production key.</remarks>
		public static int SavePrivateKeyInfo(string outputFile, string privateKey, Rsa.Format format)
		{
			return RSA_SavePrivateKeyInfo(outputFile, privateKey, (int)format);
		}

		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int RSA_SaveEncPrivateKey(string strFileOut, string strKeyString, 
			int nCount, string strPassword, int nOptions);

		/// <summary>
		/// Save a private key string to a PKCS-8 EncryptedPrivateKeyInfo file
		/// </summary>
		/// <param name="outputFile">Name of file to create</param>
		/// <param name="privateKey">Private key in internal format</param>
		/// <param name="iterationCount">Iteration count to be used when encrypting file</param>
		/// <param name="password">Password string</param>
		/// <param name="pbeOption">Type of password-based encryption to use
		/// [default = pbeWithSHAAnd3-KeyTripleDES-CBC]</param>
		/// <param name="format">File format</param>
		/// <returns>If successful, the return value is zero; otherwise it returns a nonzero <see cref="General.ErrorLookup">error code</see></returns>
		/// <overloads>Saves a private key string to a PKCS-8 EncryptedPrivateKeyInfo file</overloads>
		public static int SaveEncPrivateKey(string outputFile, string privateKey, 
			int iterationCount, string password, Rsa.PbeOptions pbeOption, Rsa.Format format)
		{
			int flags = (int)pbeOption | (int)format;
			return RSA_SaveEncPrivateKey(outputFile, privateKey, iterationCount, password, flags);
		}
		/// <summary>
		/// Save a private key string to a PKCS-8 EncryptedPrivateKeyInfo file using PBES2 algorithm
		/// </summary>
		/// <param name="outputFile">Name of file to create</param>
		/// <param name="privateKey">Private key in internal format</param>
		/// <param name="iterationCount">Iteration count to be used when encrypting file</param>
		/// <param name="password">Password string</param>
		/// <param name="cipherAlg">Block cipher to use for encryption scheme [default = des-ede3-cbc]</param>
		/// <param name="hashAlg">Hash function to use in PRF HMAC algorithm [default = hmacWithSHA1]</param>
		/// <param name="format">File format</param>
		/// <returns>If successful, the return value is zero; otherwise it returns a nonzero <see cref="General.ErrorLookup">error code</see></returns>
		public static int SaveEncPrivateKey(string outputFile, string privateKey, 
			int iterationCount, string password, CipherAlgorithm cipherAlg, HashAlgorithm hashAlg, Rsa.Format format)
		{
			int flags = PKI_PBE_PBES2 | (int)cipherAlg | (int)hashAlg | (int)format;
			return RSA_SaveEncPrivateKey(outputFile, privateKey, iterationCount, password, flags);
		}

		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int RSA_KeyBits(string strRsaKey64);

		/// <summary>
		/// Return number of significant bits in RSA key modulus.
		/// </summary>
		/// <param name="strRsaKey">Internal key string</param>
		/// <returns>Number of significant bits in key</returns>
		/// <overloads>Returns number of significant bits in RSA key modulus</overloads>
		public static int KeyBits(string strRsaKey)
		{
			return RSA_KeyBits(strRsaKey);
		}

		/// <summary>
		/// Return number of significant bits in RSA key modulus.
		/// </summary>
		/// <param name="sbRsaKey">Internal key string</param>
		/// <returns>Number of significant bits in key</returns>
		public static int KeyBits(StringBuilder sbRsaKey)
		{
			return RSA_KeyBits(sbRsaKey.ToString());
		}

		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int RSA_KeyBytes(string strRsaKey64);

		/// <summary>
		/// Return number of bytes (octets) in RSA key modulus.
		/// </summary>
		/// <param name="strRsaKey">Internal key string</param>
		/// <returns>Number of bytes in key</returns>
		/// <overloads>Returns number of bytes (octets) in RSA key modulus</overloads>
		public static int KeyBytes(string strRsaKey)
		{
			return RSA_KeyBytes(strRsaKey);
		}
		/// <summary>
		/// Return number of bytes (octets) in RSA key modulus.
		/// </summary>
		/// <param name="sbRsaKey">Internal key string</param>
		/// <returns>Number of bytes in key</returns>
		public static int KeyBytes(StringBuilder sbRsaKey)
		{
			return RSA_KeyBytes(sbRsaKey.ToString());
		}

		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int RSA_CheckKey(string strKeyString, int nOptions);
		/// <summary>
		/// Checks the validity of an "internal" RSA public or private key
		/// </summary>
		/// <param name="intKeyString">Internal key string</param>
		/// <returns>0=valid private key, 1=valid publickey, or negative <see cref="General.ErrorLookup">error code</see></returns>
		/// <remarks>A private key is also validated for consistency.</remarks>
		/// <overloads>Checks the validity of an "internal" RSA public or private key.</overloads>
		public static int CheckKey(string intKeyString)
		{
			return RSA_CheckKey(intKeyString, 0);
		}
		/// <summary>
		/// Check the validity of an "internal" RSA public or private key.
		/// </summary>
		/// <param name="sbKeyString">Internal key string</param>
		/// <returns>0=valid private key, 1=valid publickey, or negative <see cref="General.ErrorLookup">error code</see></returns>
		/// <remarks>A private key is also validated for consistency.</remarks>
		public static int CheckKey(StringBuilder sbKeyString)
		{
			return RSA_CheckKey(sbKeyString.ToString(), 0);
		}

		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int RSA_KeyHashCode(string szKeyString);

		/// <overloads>Computes the hash code of an "internal" RSA public or private key string</overloads>
		/// <summary>
		///  Compute the hash code of an "internal" RSA public or private key string.
		/// </summary>
		/// <param name="intKeyString">Internal key string</param>
		/// <returns>A 32-bit hash code for the key, or zero on error.</returns>
		/// <remarks>Should be the same for a matching private and public key.</remarks>
		public static int KeyHashCode(string intKeyString)
		{
			return RSA_KeyHashCode(intKeyString);
		}

		/// <summary>
		///  Compute the hash code of an "internal" RSA public or private key string
		/// </summary>
		/// <param name="sbKeyString">Internal key string</param>
		/// <returns>A 32-bit hash code for the key, or zero on error.</returns>
		public static int KeyHashCode(StringBuilder sbKeyString)
		{
			return RSA_KeyHashCode(sbKeyString.ToString());
		}

		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int RSA_KeyMatch(string szPrivateKey, string szPublicKey);

		/// <overloads>Verifies that a pair of "internal" RSA private and public key strings are matched.</overloads>
		/// <summary>
		/// Verify that a pair of "internal" RSA private and public key strings are matched.
		/// </summary>
		/// <param name="privateKey">Internal RSA private key string</param>
		/// <param name="publicKey">Internal RSA public key string</param>
		/// <returns>0=valid key pair, or negative <see cref="General.ErrorLookup">error code</see></returns>
		public static int KeyMatch(string privateKey, string publicKey)
		{
			return RSA_KeyMatch(privateKey, publicKey);
		}

		/// <summary>
		/// Verifies that a pair of "internal" RSA private and public key strings are matched.
		/// </summary>
		/// <param name="sbPrivateKey">Internal RSA private key string</param>
		/// <param name="sbPublicKey">Internal RSA public key string</param>
		/// <returns>0=valid key pair, or negative <see cref="General.ErrorLookup">error code</see></returns>
		public static int KeyMatch(StringBuilder sbPrivateKey, StringBuilder sbPublicKey)
		{
			return RSA_KeyMatch(sbPrivateKey.ToString(), sbPublicKey.ToString());
		}

		/// <summary>
		/// Options when converting between internal RSA key and XML
		/// </summary>
		[Flags()]
		public enum XmlOptions
		{
			/// <summary>
			/// Exclude private key parameters
			/// </summary>
			ExcludePrivateParams = PKI_XML_EXCLPRIVATE,
			/// <summary>
			/// Create XML in .NET-compatible RSAKeyValue format (ToXML only)
			/// </summary>
			ForceRSAKeyValue = PKI_XML_RSAKEYVALUE,
			/// <summary>
			/// Create XML in non-standard hex format (ToXML only)
			/// </summary>
			HexBinaryFormat = PKI_XML_HEXBINARY,
			/// <summary>
			/// Require private key to exist in the XML input or fail (FromXML only)
			/// </summary>
			RequirePrivate = PKI_XML_REQPRIVATE,
		}

		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int RSA_ToXMLStringEx(StringBuilder sbOutput, int nOutputLen,  string szKeyString, string prefix, int nOptions);
		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int RSA_FromXMLString(StringBuilder sbOutput, int nOutputLen, string szXmlString, int nOptions);

		/// <overloads>Create an XML string representation of an RSA internal key string</overloads>
		/// <summary>
		/// Create an XML string representation of an RSA internal key string.
		/// </summary>
		/// <param name="intKeyString">Internal key string</param>
		/// <param name="options">Option flags: set as zero for defaults.</param>
		/// <returns>XML string or empty string on error</returns>
		public static string ToXMLString(string intKeyString, XmlOptions options)
		{
			StringBuilder sb = new StringBuilder(0);
			int n = RSA_ToXMLStringEx(sb, 0, intKeyString, "", (int)options);
			if (n <= 0) return String.Empty;
			sb = new StringBuilder(n);
			RSA_ToXMLStringEx(sb, sb.Capacity, intKeyString, "", (int)options);
			return sb.ToString();
		}

		/// <summary>
		/// Create an XML string representation of an RSA internal key string with option to add a namespace prefix.
		/// </summary>
		/// <param name="intKeyString">Internal key string</param>
		/// <param name="prefix">Prefix to add to elements, e.g. <c>"ds"</c> or <c>"ds:"</c>.</param>
		/// <param name="options">Option flags: set as zero for defaults.</param>
		/// <returns>XML string or empty string on error</returns>
		/// <remarks>Use this extended function to add a namespace prefix to all elements in the XML output; for example, &lt;ds:RSAKeyValue&gt;. 
		/// Note that it's up to the user to map the prefix to a URI somewhere in the final XML document. </remarks>
		public static string ToXMLString(string intKeyString, string prefix, XmlOptions options)
		{
			StringBuilder sb = new StringBuilder(0);
			int n = RSA_ToXMLStringEx(sb, 0, intKeyString, prefix, (int)options);
			if (n <= 0) return String.Empty;
			sb = new StringBuilder(n);
			RSA_ToXMLStringEx(sb, sb.Capacity, intKeyString, prefix, (int)options);
			return sb.ToString();
		}

		/// <overloads>Create an RSA key string in internal format from an XML string,</overloads>
		/// <summary>
		/// Create an RSA key string in internal format from an XML string.
		/// </summary>
		/// <param name="xmlString">The XML string to use to reconstruct the RSA key</param>
		/// <returns>Key string in internal format or empty string on error</returns>
		/// <remarks>Creates an internal private key string if the XML contains private key parameters, otherwise an internal public key string.</remarks>
		public static string FromXMLString(string xmlString)
		{
			StringBuilder sb = new StringBuilder(0);
			int flags = 0;
			int n = RSA_FromXMLString(sb, 0, xmlString, flags);
			if (n <= 0) return String.Empty;
			sb = new StringBuilder(n);
			RSA_FromXMLString(sb, sb.Capacity, xmlString, flags);
			return sb.ToString();
		}

		/// <summary>
		/// Create an RSA key string in internal format from an XML string with options.
		/// </summary>
		/// <param name="xmlString">The XML string to use to reconstruct the RSA key</param>
		/// <param name="options">Option flags: set as zero for defaults.</param>
		/// <returns>Key string in internal format or empty string on error</returns>
		public static string FromXMLString(string xmlString, XmlOptions options)
		{
			StringBuilder sb = new StringBuilder(0);
			int flags = (int)options;
			int n = RSA_FromXMLString(sb, 0, xmlString, flags);
			if (n <= 0) return String.Empty;
			sb = new StringBuilder(n);
			RSA_FromXMLString(sb, sb.Capacity, xmlString, flags);
			return sb.ToString();
		}

		/// <summary>
		/// Create an RSA key string in internal format from an XML string with flag to exclude private key details.
		/// </summary>
		/// <param name="xmlString">The XML string to use to reconstruct the RSA key</param>
		/// <param name="excludePrivateParams">Reconstruct public key details only</param>
		/// <returns>Key string in internal format or empty string on error</returns>
		public static string FromXMLString(string xmlString, bool excludePrivateParams)
		{
			StringBuilder sb = new StringBuilder(0);
			int flags = (excludePrivateParams ? PKI_XML_EXCLPRIVATE : 0);
			int n = RSA_FromXMLString(sb, 0, xmlString, flags);
			if (n <= 0) return String.Empty;
			sb = new StringBuilder(n);
			RSA_FromXMLString(sb, sb.Capacity, xmlString, flags);
			return sb.ToString();
		}

		/* 'RAW' RSA ENCRYPTION/DECRYPTION FUNCTIONS */
		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int RSA_RawPublic(byte[] abData, int nDataLen, 
			string publicKeyStr, int nOptions);
		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int RSA_RawPrivate(byte[] abData, int nDataLen, 
			string privateKeyStr, int nOptions);

		/// <overloads>Carry out RSA transformation using public key</overloads>
		/// <summary>
		/// Carry out RSA transformation using public key
		/// </summary>
		/// <param name="data">Data (<b>must</b> be same byte length as key modulus)</param>
		/// <param name="publicKeyStr">Public key in internal string format</param>
		/// <returns>Transformed data</returns>
		public static byte[] RawPublic(byte[] data, string publicKeyStr)
		{
			byte[] b = new byte[data.Length];
			Array.Copy(data, b, data.Length);
			int r = RSA_RawPublic(b, b.Length, publicKeyStr, 0);
			if (r != 0) return new byte[0];
			return b;
		}

		/// <summary>
		/// Carry out RSA transformation using public key (with specialist options)
		/// </summary>
		/// <param name="data">Data (<b>must</b> be same byte length as key modulus)</param>
		/// <param name="publicKeyStr">Public key in internal string format</param>
		/// <param name="options">Specialist options value</param>
		/// <returns>Transformed data</returns>
		public static byte[] RawPublic(byte[] data, string publicKeyStr, int options)
		{
			byte[] b = new byte[data.Length];
			Array.Copy(data, b, data.Length);
			int r = RSA_RawPublic(b, b.Length, publicKeyStr, options);
			if (r != 0) return new byte[0];
			return b;
		}

		/// <overloads>Carry out RSA transformation using private key</overloads>
		/// <summary>
		/// Carry out RSA transformation using private key
		/// </summary>
		/// <param name="data">Data (<b>must</b> be same byte length as key modulus)</param>
		/// <param name="privateKeyStr">Private key in internal string format</param>
		/// <returns>Transformed data</returns>
		public static byte[] RawPrivate(byte[] data, string privateKeyStr)
		{
			byte[] b = new byte[data.Length];
			Array.Copy(data, b, data.Length);
			int r = RSA_RawPrivate(b, b.Length, privateKeyStr, 0);
			if (r != 0) return new byte[0];
			return b;
		}
		/// <summary>
		/// Carry out RSA transformation using private key (with specialist options)
		/// </summary>
		/// <param name="data">Data (<b>must</b> be same byte length as key modulus)</param>
		/// <param name="privateKeyStr">Private key in internal string format</param>
		/// <param name="options">Specialist options value</param>
		/// <returns>Transformed data</returns>
		public static byte[] RawPrivate(byte[] data, string privateKeyStr, int options)
		{
			byte[] b = new byte[data.Length];
			Array.Copy(data, b, data.Length);
			int r = RSA_RawPrivate(b, b.Length, privateKeyStr, options);
			if (r != 0) return new byte[0];
			return b;
		}
		
		/// <summary>
		/// Type of encoding to apply (or use to decode). <em>OBSOLETE.</em>
		/// </summary>
		[ObsoleteAttribute("There is a better alternative!", false)]
		public enum EncodeFor
		{
			/// <summary>
			/// EME-PKCS1-V1_5
			/// </summary>
			Encryption = 0,
			/// <summary>
			/// EME-OAEP
			/// </summary>
			Encryption_OAEP = 0x10,
			/// <summary>
			/// EMSA-PKCS1-V1_5 (using SHA-1)
			/// </summary>
			Signature = 0x20,
		}

		/// <summary>
		/// Encoding method for encryption
		/// </summary>
		/// <remarks>See PKCS#1 v2.1 or [<a href="https://tools.ietf.org/html/rfc3447">RFC3447</a>]</remarks>
		public enum EME
		{
			/// <summary>
			/// EME-PKCS1-v1_5 encoding method
			/// </summary>
			PKCSv1_5 = 0,
			/// <summary>
			/// EME-OAEP encoding method
			/// </summary>
			OAEP = 0x10,
		}

		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int RSA_EncodeMsg(byte[] abOutput, int nOutputLen, 
			byte[] abMessage, int nMsgLen, int nOptions);
		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int RSA_DecodeMsg(byte[] abOutput, int nOutputLen, 
			byte[] abInput, int nInputLen, int nOptions);

		/// <summary>
		/// Encode a message ready for "raw" RSA encryption or signing. <em>OBSOLETE.</em>
		/// </summary>
		/// <param name="keyBytes">Size of RSA key in bytes</param>
		/// <param name="message">Message data</param>
		/// <param name="method">Method to use</param>
		/// <returns>Encoded message block</returns>
		/// <remarks><em>OBSOLETE</em>. Use <c>EncodeMsgForEncryption</c> 
		/// or <c>EncodeMsgForSignature</c> or <c>EncodeDigestForSignature</c></remarks>
		[Obsolete("Use Rsa.EncodeMsgForEncryption() or Rsa.EncodeMsgForSignature() or Rsa.EncodeDigestForSignature() instead", false)]
		public static byte[] EncodeMsg(int keyBytes, byte[] message, Rsa.EncodeFor method)
		{
			if (keyBytes <= 0) return new Byte[0];
			byte[] b = new byte[keyBytes];
			int r = RSA_EncodeMsg(b, b.Length, message, message.Length, (int)method);
			if (r != 0) return new byte[0];
			return b;
		}
		/// <summary>
		/// Decode a PKCS-1 encoded block. <em>OBSOLETE.</em>
		/// </summary>
		/// <param name="data">Binary data to be decoded</param>
		/// <param name="method">Method to use</param>
		/// <returns>Decoded data</returns>
		/// <remarks><em>OBSOLETE</em>. Use <c>DecodeMsgForEncryption</c> or <c>DecodeDigestForSignature</c></remarks>
		[Obsolete("Use Rsa.DecodeMsgForEncryption() or Rsa.DecodeDigestForSignature() instead", false)]
		public static byte[] DecodeMsg(byte[] data, Rsa.EncodeFor method)
		{
			int n = RSA_DecodeMsg(null, 0, data, data.Length, (int)method);
			if (n <= 0) return new byte[0];
			byte[] b = new byte[n];
			n = RSA_DecodeMsg(b, b.Length, data, data.Length, (int)method);
			if (n < 0) return new byte[0];
			return b;
		}

		/// <summary>
		/// Encode a message for encryption
		/// </summary>
		/// <param name="keyBytes">Number of bytes in the key</param>
		/// <param name="message">Message to be encoded</param>
		/// <param name="method">Encoding method to use</param>
		/// <returns>Encoded message block</returns>
		public static byte[] EncodeMsgForEncryption(int keyBytes, byte[] message, Rsa.EME method)
		{
			if (keyBytes <= 0) return new Byte[0];
			byte[] b = new byte[keyBytes];
			int r = RSA_EncodeMsg(b, b.Length, message, message.Length, (int)method);
			if (r != 0) return new byte[0];
			return b;
		}
		/// <summary>
		/// Decode a message for encryption
		/// </summary>
		/// <param name="data">Encoded message</param>
		/// <param name="method">Encoding method used</param>
		/// <returns>Decoded message</returns>
		public static byte[] DecodeMsgForEncryption(byte[] data, Rsa.EME method)
		{
			int n = RSA_DecodeMsg(null, 0, data, data.Length, (int)method);
			if (n <= 0) return new byte[0];
			byte[] b = new byte[n];
			n = RSA_DecodeMsg(b, b.Length, data, data.Length, (int)method);
			if (n < 0) return new byte[0];
			return b;
		}
		/// <summary>
		/// Encode a message for signature
		/// </summary>
		/// <param name="keyBytes">Number of bytes in the key</param>
		/// <param name="message">Message to be encoded</param>
		/// <param name="hashAlg">Message digest algorithm to use</param>
		/// <returns>Encoded block</returns>
		/// <remarks>Only EMSA-PKCS1-v1_5 is supported. 
		/// Note we can only ever recover the <em>digest</em> from the 
		/// encoded block.</remarks>
		public static byte[] EncodeMsgForSignature(int keyBytes, byte[] message, HashAlgorithm hashAlg)
		{
			int options = (int)hashAlg + (int)Emsig.PKI_EMSIG_DEFAULT;
			if (keyBytes <= 0) return new Byte[0];
			byte[] b = new byte[keyBytes];
			int r = RSA_EncodeMsg(b, b.Length, message, message.Length, options);
			if (r != 0) return new byte[0];
			return b;
		}
		/// <summary>
		/// Encode a message digest for signature
		/// </summary>
		/// <param name="keyBytes">Number of bytes in the key</param>
		/// <param name="digest">Digest of message</param>
		/// <param name="hashAlg">Message digest algorithm used to create digest</param>
		/// <returns>Encoded block</returns>
		/// <remarks>Only EMSA-PKCS1-v1_5 is supported.</remarks>
		public static byte[] EncodeDigestForSignature(int keyBytes, byte[] digest, HashAlgorithm hashAlg)
		{
			int options = (int)hashAlg + (int)Emsig.PKI_EMSIG_DEFAULT + (int)Emsig.PKI_EMSIG_DIGESTONLY;
			if (keyBytes <= 0) return new Byte[0];
			byte[] b = new byte[keyBytes];
			int r = RSA_EncodeMsg(b, b.Length, digest, digest.Length, options);
			if (r != 0) return new byte[0];
			return b;
		}

		/// <overloads>Decode an encoded message for signature</overloads>
		/// <summary>
		/// Decode an encoded message for signature
		/// </summary>
		/// <param name="data">Encoded message for signature</param>
		/// <returns>Decoded message digest or an empty array on error</returns>
		/// <remarks>Only EMSA-PKCS1-v1_5 is supported.</remarks>
		public static byte[] DecodeDigestForSignature(byte[] data)
		{
			const int options = (int)Emsig.PKI_EMSIG_DEFAULT;
			int n = RSA_DecodeMsg(null, 0, data, data.Length, options);
			if (n <= 0) return new byte[0];
			byte[] b = new byte[n];
			n = RSA_DecodeMsg(b, b.Length, data, data.Length, options);
			if (n < 0) return new byte[0];
			return b;
		}
		/// <summary>
		/// Decode an encoded message for signature 
		/// </summary>
		/// <param name="data">Encoded message for signature</param>
		/// <param name="getFullDigestInfo">If true, extract the full <c>DigestInfo</c>;
		/// otherwise just extract the message digest itself</param>
		/// <returns>Decoded data or an empty array on error</returns>
		/// <remarks>Only EMSA-PKCS1-v1_5 is supported.</remarks>
		public static byte[] DecodeDigestForSignature(byte[] data, bool getFullDigestInfo)
		{
			int options;
			if (getFullDigestInfo)
				options  = (int)Emsig.PKI_EMSIG_DEFAULT + (int)Emsig.PKI_EMSIG_DIGINFO;
			else
				options = (int)Emsig.PKI_EMSIG_DEFAULT;
			int n = RSA_DecodeMsg(null, 0, data, data.Length, options);
			if (n <= 0) return new byte[0];
			byte[] b = new byte[n];
			n = RSA_DecodeMsg(b, b.Length, data, data.Length, options);
			if (n < 0) return new byte[0];
			return b;
		}

		/// <summary>
		/// Encode a message using ISO/IEC 9796-1 formatting
		/// </summary>
		/// <param name="message">message to be encoded</param>
		/// <param name="keyBits">exact length of key in <em>bits</em></param>
		/// <returns>Padded message block ready for signing or an empty array on error</returns>
		/// <remarks>The output block will be the same size as the key rounded up to the next whole byte.
		/// The message must be no longer than half the key length.</remarks>
		/// <seealso cref="Rsa.DecodeMsgIso9796"/>
		public static byte[] EncodeMsgIso9796(byte[] message, int keyBits)
		{
			int options;
			options = (int)Emsig.PKI_EMSIG_ISO9796 + keyBits;
			if (keyBits <= 0) return new Byte[0];
			int keyBytes = (keyBits + 7) / 8;
			byte[] b = new byte[keyBytes];
			int r = RSA_EncodeMsg(b, b.Length, message, message.Length, options);
			if (r != 0) return new byte[0];
			return b;
		}

		/// <summary>
		/// Decode a message padded using ISO/IEC 9796-1 formatting  
		/// </summary>
		/// <param name="data">encoded message for signature</param>
		/// <param name="keyBits">exact length of key in <em>bits</em></param>
		/// <returns>Recovered message or an empty array on error</returns>
		/// <seealso cref="Rsa.EncodeMsgIso9796"/>
		public static byte[] DecodeMsgIso9796(byte[] data, int keyBits)
		{
			int options;
			options = (int)Emsig.PKI_EMSIG_ISO9796 + keyBits;
			if (keyBits <= 0) return new Byte[0];
			int n = RSA_DecodeMsg(null, 0, data, data.Length, options);
			if (n <= 0) return new byte[0];
			byte[] b = new byte[n];
			n = RSA_DecodeMsg(b, b.Length, data, data.Length, options);
			if (n < 0) return new byte[0];
			return b;
		}

		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int RSA_KeyValue(StringBuilder szOutput, int nOutChars, string szKeyString, string szFieldName, int nOptions);

		/// <summary>
		/// Extract a base64-encoded RSA key value from internal key string
		/// </summary>
		/// <param name="keyString">Public or private key in internal string format</param>
		/// <param name="fieldName">Name of field to be extracted: <c>"Modulus"</c> or <c>"Exponent"</c></param>
		/// <returns>Value encoded in base64 or an empty string on error</returns>
		/// <remarks>The output is a continuous string of base64 characters 
		/// suitable for a <c>&lt;RSAKeyValue&gt;</c> node in an XML-DSIG document.</remarks>
		public static string KeyValue(string keyString, string fieldName)
		{
			int n = RSA_KeyValue(null, 0, keyString, fieldName, 0);
			if (n <= 0) return "";
			StringBuilder sb = new StringBuilder(n);
			RSA_KeyValue(sb, n, keyString, fieldName, 0);
			return sb.ToString();
		}

	}

	/// <summary>
	/// PKCS-12 (PFX) File Functions
	/// </summary>
	public class Pfx
	{
		private const int PKI_PFX_NO_PRIVKEY = 0x10;

		private Pfx()
		{}	// Static methods only, so hide constructor.

		/// <summary>
		/// Specialist options.
		/// </summary>
		[Flags()]
		public enum Options
		{
			/// <summary>
			/// Default options
			/// </summary>
			Default = 0,
			/// <summary>
			/// Store the certificate in unencrypted form (default is encrypted with 40-bit RC2)
			/// </summary>
			PlainCert = 0x2000000,
			/// <summary>
			/// Store the private key in the exact form of the pkcs-8 input file (default is to re-encrypt with Triple DES)
			/// </summary>
			CloneKey = 0x4000000,
			/// <summary>
			/// Create a PFX file with the exact peculiarities used by Microsoft (default is OpenSSL)
			/// </summary>
			AltFormat = 0x100000,
			/// <summary>
			/// Create the output file in PEM format (default is DER-encoded binary)
			/// </summary>
			FormatPem = 0x10000,
		}


		/* PKCS12 FILE FUNCTIONS */
		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int PFX_MakeFile(string strFileOut, string strCertFile, string strKeyFile, string strPassword, 
			string strFriendlyName, int options);

		/// <summary>
		/// Create a PFX (PKCS-12) file from an X.509 certificate and (optional) encrypted private key file
		/// with advanced options.
		/// </summary>
		/// <param name="fileToMake">name of output file to be created</param>
		/// <param name="certFile">filename of the subject's X.509 certificate (required)</param>
		/// <param name="privateKeyFile">filename of the subject's encrypted private key in pkcs-8 format (optional)</param>
		/// <param name="password">password for private key file and new PFX file</param>
		/// <param name="friendlyName">friendly name identification for the subject (optional)</param>
		/// <param name="pfxOptions">Specialist options</param>
		/// <returns>Zero if successful or a non-zero <see cref="General.ErrorLookup">error code</see>.</returns>
		/// <overloads>Creates a PFX (PKCS-12) file from an X.509 certificate and encrypted private key file.</overloads>
		public static int MakeFile(string fileToMake, string certFile, string privateKeyFile,
			string password, string friendlyName, Pfx.Options pfxOptions)
		{
			return PFX_MakeFile(fileToMake, certFile, privateKeyFile, password, friendlyName, (int)pfxOptions);
		}

		/// <summary>
		/// Create a simple PFX file from an X.509 certificate and encrypted private key file
		/// [deprecated]
		/// </summary>
		/// <param name="fileToMake">name of output file to be created</param>
		/// <param name="certFile">filename of the subject's X.509 certificate (required in all cases)</param>
		/// <param name="privateKeyFile">filename of the subject's encrypted private key in pkcs-8 format</param>
		/// <param name="password">password for private key file</param>
		/// <param name="friendlyName">friendly name identification for the subject (optional)</param>
		/// <param name="excludePrivateKey"><c>true</c> to exclude the private key data (i.e. just include the certificate)</param>
		/// <returns>Zero if successful or a non-zero <see cref="General.ErrorLookup">error code</see>.</returns>
		public static int MakeFile(string fileToMake, string certFile, string privateKeyFile, 
			string password, string friendlyName, bool excludePrivateKey)
		{
			// [2009-03-07] Changed '1' to proper flag in options
			return PFX_MakeFile(fileToMake, certFile, privateKeyFile, password, friendlyName, 
				(excludePrivateKey ? PKI_PFX_NO_PRIVKEY : 0));
		}

		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int PFX_VerifySig(string strFileName, string strPassword, int options);
		/// <summary>
		/// Verify that the MacData signature in PKCS-12 file is OK
		/// </summary>
		/// <param name="fileName">Name of PKCS-12 file to be checked</param>
		/// <param name="password">password for file</param>
		/// <returns><c>true</c> if signature is OK</returns>
		public static bool SignatureIsValid(string fileName, string password)
		{
			int r = PFX_VerifySig(fileName, password, 0);
			return (0 == r ? true : false);
		}

	}

	/// <summary>
	/// X.509 Certificate Functions
	/// </summary>
	public class X509
	{
		private X509()
		{}	// Static methods only, so hide constructor.

		private const int PKI_X509_NO_TIMECHECK = 0x200000;
		private const int PKI_PFX_P7CHAIN = 0x0400;

		/// <summary>
		/// Return value from <see cref="X509.CertIsValidNow">X509.CertIsValidNow</see>
		/// indicating that the certificate has expired.
		/// </summary>
		public const int Expired = -1;

		/// <summary>
		/// Return value from <see cref="X509.VerifyCert">X509.VerifyCert</see> indicating failure.
		/// </summary>
		public const int Failure = -1;

		/// <summary>
		/// Return value from <see cref="X509.ValidatePath(string)">X509.ValidatePath</see>
		/// indicating that the certificate path is invalid.
		/// </summary>
		public const int Invalid = 1;

		/// <summary>
		/// Return value from <see cref="X509.CheckCertInCRL">X509.CheckCertInCRL</see>
		/// indicating that the certificate is revoked.
		/// </summary>
		public const int Revoked = 1;

		/// <summary>
		/// Options to create X.509 certificate/CRL/certificate signing request
		/// </summary>
		/// <remarks>Only include <b>one</b> SigAlg option for the signature algorithm.</remarks>
		[Flags()]
		public enum Options
		{
			/// <summary>
			/// Default options
			/// </summary>
			None = 0,
			/// <summary>
			/// Sign with sha1WithRSAEncryption (rsa-sha1)
			/// </summary>
			SigAlg_Sha1WithRSAEncryption = 0,
			/// <summary>
			/// Sign with md5WithRSAEncryption (rsa-md5)
			/// </summary>
			SigAlg_Md5WithRSAEncryption = 1,
			/// <summary>
			/// Sign with md2WithRSAEncryption (Legacy apps only)
			/// </summary>
			SigAlg_Md2WithRSAEncryption    = 2,
			/// <summary>
			/// Sign with sha256WithRSAEncryption (rsa-sha256)
			/// </summary>
			SigAlg_Sha256WithRSAEncryption = 3,
			/// <summary>
			/// Sign with sha384WithRSAEncryption (rsa-sha384)
			/// </summary>
			SigAlg_Sha384WithRSAEncryption = 4,
			/// <summary>
			/// Sign with sha512WithRSAEncryption (rsa-sha512)
			/// </summary>
			SigAlg_Sha512WithRSAEncryption = 5,
			/// <summary>
			/// Sign with sha224WithRSAEncryption (rsa-sha224)
			/// </summary>
			SigAlg_Sha224WithRSAEncryption = 6,

			/// <summary>
			/// Create in PEM (base64) format (default for CSR request)
			/// </summary>
			FormatPem = 0x10000,
			/// <summary>
			/// Create in binary format (default for certificate)
			/// </summary>
			FormatBinary = 0x20000,
			/// <summary>
			/// Create a request with the "kludge" that omits the strictly mandatory attributes completely 
			/// [default = include attributes with zero-length field]
			/// </summary>
			RequestKludge = 0x100000,
			/// <summary>
			/// Re-encode Unicode or UTF-8 string as Latin-1, if possible
			/// </summary>
			Latin1 = 0x400000,
			/// <summary>
			/// Encode distinguished name as UTF8String [default = PrintableString]
			/// </summary>
			UTF8String = 0x800000,
			/// <summary>
			/// Output distinguished name in LDAP string representation
			/// </summary>
			Ldap = 0x1000,
			/// <summary>
			/// Output serial number in decimal format [default = hex]
			/// </summary>
			Decimal = 0x8000,
			/// <summary>
			/// Disable the BasicConstraints extension [default = include] 
			/// </summary>
			NoBasicConstraints = 0x2000000,
			/// <summary>
			/// Set the BasicConstraints subject type to be a CA [default = End Entity]
			/// </summary>
			SetAsCA = 0x4000000,
			/// <summary>
			/// Create a Version 1 certificate, i.e. no extensions [default = Version 3]
			/// </summary>
			VersionOne = 0x8000000,
			/// <summary>
			/// Add the issuer's KeyIdentifier, if present, as an AuthorityKeyIdentifer [default = do not add]
			/// </summary>
			AuthKeyId = 0x1000000,
		}

		/// <summary>
		/// Options for key usage in certificate
		/// </summary>
		/// <remarks>These should be self-explanatory</remarks>
		[Flags()]
		public enum KeyUsageOptions
		{
			/// <summary>
			/// 
			/// </summary>
			None = 0,
			/// <summary>
			/// 
			/// </summary>
			DigitalSignature = 0x0001,
			/// <summary>
			/// 
			/// </summary>
			NonRepudiation = 0x0002,
			/// <summary>
			/// 
			/// </summary>
			KeyEncipherment = 0x0004,
			/// <summary>
			/// 
			/// </summary>
			DataEncipherment = 0x0008,
			/// <summary>
			/// 
			/// </summary>
			KeyAgreement = 0x0010,
			/// <summary>
			/// 
			/// </summary>
			KeyCertSign = 0x0020,
			/// <summary>
			/// 
			/// </summary>
			CrlSign = 0x0040,
			/// <summary>
			/// 
			/// </summary>
			EncipherOnly = 0x0080,
			/// <summary>
			/// 
			/// </summary>
			DecipherOnly = 0x0100,
		}

		/* X509 CERTIFICATE FUNCTIONS */
		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int X509_MakeCert(string certfile, string issuerCert, 
			string subjectPubkeyFile, string issuerPvkInfoFile,
			int certnum, int yearsvalid, string distName, string email,  
			int keyUsageFlags, string password, int optionFlags);

		/// <summary>
		/// Creates a new X.509 certificate using subject's public key and issuer's private key files.
		/// </summary>
		/// <param name="certFile">Name of file to be created</param>
		/// <param name="issuerCert">Name of issuer's certificate file</param>
		/// <param name="subjectPubkeyFile">File containing subjects public key data</param>
		/// <param name="issuerPvkInfoFile">File containing issuer's private key data</param>
		/// <param name="certNum">Issue number for new certificate</param>
		/// <param name="yearsValid">How many years to be valid</param>
		/// <param name="distName">Distinguished name string.
		/// See <see href="http://www.cryptosys.net/pki/manpki/pki_distnames.html">Distinguished Names</see> in the main manual.</param>
		/// <param name="extensions">Extensions: a list of attribute-value pairs separated by semicolons (;). 
		/// See <see href="http://www.cryptosys.net/pki/manpki/pki_x509extensions.html">X.509 Extensions Parameter</see> in the main manual.</param>
		/// <param name="keyUsageOptions">Key usage options</param>
		/// <param name="password">For issuer's private key</param>
		/// <param name="options">Option flags: set as zero for defaults.</param>
		/// <returns>Zero if successful or a non-zero <see cref="General.ErrorLookup">error code</see></returns>
		/// <remarks>
		/// Valid extensions are:
		/// <list type="table">
		/// <item>
		/// <term><b>rfc822Name</b>=string;</term>
		/// <description>To set the rfc822 email address in the <c>subjectAltName</c> extension, 
		/// e.g. <c>rfc822Name=myname@testorg.com</c>.</description>
		/// </item>
		/// <item>
		/// <term><b>serialNumber</b>=hex-digits;</term>
		/// <description>To override the serial number set by <c>certNum</c> with a larger, 
		/// unlimited integer in hexadecimal format, 
		/// e.g. <c>serialNumber=12deadbeefcafe0123</c>.</description>
		/// </item>
		/// <item>
		/// <term><b>subjectKeyIdentifier</b>=hex-digits;</term>
		/// <description>To set the <c>subjectAltName</c> extension with an octet string (binary) value specified in hex format 
		/// e.g. <c>subjectKeyIdentifier=fedcba9876543210</c>.</description>
		/// </item>
		/// <item>
		/// <term><b>notAfter</b>=iso-date-string;</term>
		/// <description>To override the validity period set by <c>yearsValid</c> with a specific date and time in ISO format, 
		/// e.g. <c>notAfter=2020-12-31</c> or <c>notAfter=2020-12-31T14:03:59</c>. 
		/// If no time is given it will default to 23:59:59. Note that this time is UTC (GMT) not local. 
		/// </description>
		/// </item>
		/// <item>
		/// <term><b>notBefore</b>=iso-date-string;</term>
		/// <description>To override the default start time from one minute ago to a specific date and time in ISO format, 
		/// e.g. <c>notBefore=2008-12-31</c>. If no time is given it will default to 00:00:01. 
		/// Note that this time is UTC (GMT) not local. 
		/// </description>
		/// </item>
		/// </list>
		///
		/// <para>
		/// As an alternative, you can create a new X.509 certificate using a PKCS-10 certificate signing request (CSR) file. 
		/// Pass the name of the CSR file in the subjectPubkeyFile parameter and set the distName empty <c>""</c>. 
		/// The empty distinguished name parameter is a flag that a CSR file is being used.
		/// </para>
		/// </remarks>
		public static int MakeCert(string certFile, string issuerCert,
			string subjectPubkeyFile, string issuerPvkInfoFile,
			int certNum, int yearsValid, string distName, string extensions,
			KeyUsageOptions keyUsageOptions, string password, Options options)
		{
			int r = X509_MakeCert(certFile, issuerCert, 
				subjectPubkeyFile, issuerPvkInfoFile,
				certNum, yearsValid, distName, extensions,  
				(int)keyUsageOptions, password, (int)options);
			return r;
		}

		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int X509_MakeCertSelf(string certfile, string epkfile, 
			int certnum, int yearsvalid, string distName, string email,
			int keyUsageFlags, string password, int optionFlags);
		/// <summary>
		/// Creates a self-signed X.509 certificate
		/// </summary>
		/// <param name="certFile">Name of file to be created</param>
		/// <param name="privateKeyFile">File containing issuer's private key data</param>
		/// <param name="certNum">Issue number for new certificate</param>
		/// <param name="yearsValid">How many years to be valid</param>
		/// <param name="distName">Distinguished name string.
		/// See <see href="http://www.cryptosys.net/pki/manpki/pki_distnames.html">Distinguished Names</see> in the main manual.</param>
		/// <param name="extensions">Extensions: a list of attribute-value pairs separated by semicolons (;). 
		/// See <see href="http://www.cryptosys.net/pki/manpki/pki_x509extensions.html">X.509 Extensions Parameter</see> in the main manual.</param>
		/// <param name="keyUsageOptions">Key usage options</param>
		/// <param name="password">For issuer's private key</param>
		/// <param name="options">Option flags: set as zero for defaults.</param>
		/// <returns>Zero if successful or a non-zero <see cref="General.ErrorLookup">error code</see></returns>
		public static int MakeCertSelf(string certFile, string privateKeyFile,
			int certNum, int yearsValid, string distName, string extensions,
			KeyUsageOptions keyUsageOptions, string password, Options options)
		{
			int r = X509_MakeCertSelf(certFile, privateKeyFile,
				certNum, yearsValid, distName, extensions,  
				(int)keyUsageOptions, password, (int)options);
			return r;
		}

		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int X509_CertRequest(string reqfile, string epkfile, 
			string distName, string reserved, string password, int optionFlags);
		/// <summary>
		/// Creates a PKCS #10 certificate signing request (CSR) using the subject's private key file
		/// </summary>
		/// <param name="reqFile">Name of Certificate Signing Request file to be created</param>
		/// <param name="privateKeyFile">Name of subject's encrypted private key file</param>
		/// <param name="distName">Specifying the subject's distinguished name as a set of attribute key=value pairs
		/// separated with semi-colons (;)</param>
		/// <param name="password">password for Subject's encrypted private key file</param>
		/// <param name="options">Option flags: set as zero for defaults.</param>
		/// <returns>Zero if successful or a non-zero <see cref="General.ErrorLookup">error code</see></returns>
		/// <overloads>Create a PKCS #10 certificate signing request (CSR)</overloads>
		public static int CertRequest(string reqFile, string privateKeyFile,
			string distName, string password, Options options)
		{
			int r = X509_CertRequest(reqFile, privateKeyFile, 
				distName, "", password, (int)options);
			return r;
		}

		/// <summary>
		/// Creates a PKCS #10 certificate signing request (CSR) with extensions
		/// </summary>
		/// <param name="reqFile">Name of Certificate Signing Request file to be created</param>
		/// <param name="privateKeyFile">Name of subject's encrypted private key file</param>
		/// <param name="distName">Specifying the subject's distinguished name as a set of attribute key=value pairs
		/// separated with semi-colons (;).
		/// See <a href="http://www.cryptosys.net/pki/manpki/pki_distnames.html">Specifying Distinguished Names</a>
		/// </param>
		/// <param name="extensions">A list of attribute-value pairs
		/// to be included in an <c>extensionRequest</c> field.
		/// See <a href="http://www.cryptosys.net/pki/manpki/pki_x509extensions.html">X.509 Extensions</a>
		/// </param>
		/// <param name="password">password for Subject's encrypted private key file</param>
		/// <param name="options">Option flags: set as zero for defaults.</param>
		/// <returns>Zero if successful or a non-zero <see cref="General.ErrorLookup">error code</see></returns>
		public static int CertRequest(string reqFile, string privateKeyFile,
			string distName, string extensions, string password, Options options)
		{
			int r = X509_CertRequest(reqFile, privateKeyFile,
				distName, extensions, password, (int)options);
			return r;
		}

		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int X509_VerifyCert(string strCertToVerify, string strIssuerCert, int flags);
		/// <summary>
		/// Verifies that an X.509 certificate has been signed by its issuer
		/// </summary>
		/// <param name="certToVerify">Filename of certificate to verify</param>
		/// <param name="issuerCert">Filename of purported issuer's certificate</param>
		/// <returns>Zero if the certificate's signature is valid; 
		/// <see cref="X509.Failure">X509.Failure</see> (-1) if the validation fails; 
		/// otherwise a positive <see cref="General.ErrorLookup">error code</see>.
		/// </returns>
		/// <remarks>This can also be used to verify that an X.509 Certificate Revocation List (CRL) 
		/// or PKCS#10 Certification Signing Request (CSR) has been signed by the owner of the issuer's certificate. 
		/// Just pass the name of the file (or its base64/PEM string form) as <c>certToVerify</c>.</remarks>
		public static int VerifyCert(string certToVerify, string issuerCert)
		{
			int r = X509_VerifyCert(certToVerify, issuerCert, 0);
			return r;
		}
		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int X509_CertThumb(string strCertFile, StringBuilder sbHash, int hashlen, int flags);
		/// <summary>
		/// Calculates the thumbprint (message digest hash) of an X.509 certificate
		/// </summary>
		/// <param name="certFile">Filename of certificate file (or its base64 representation)</param>
		/// <param name="hashAlg">HashAlgorithm</param>
		/// <returns>String containing the message digest in hexadecimal format</returns>
		public static string CertThumb(string certFile, HashAlgorithm hashAlg)
		{
			StringBuilder sb = new StringBuilder(0);
			int n = X509_CertThumb(certFile, sb, 0, (int)hashAlg);
			if (n <= 0) return string.Empty;
			sb = new StringBuilder(n);
			X509_CertThumb(certFile, sb, sb.Capacity, (int)hashAlg);
			return sb.ToString();
		}
		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int X509_CertIsValidNow(string strCertFile, int flags);
		/// <summary>
		/// Verifies that an X.509 certificate is currently valid as per system clock
		/// </summary>
		/// <param name="certFile">Filename of certificate file (or its base64 representation)</param>
		/// <returns>True if certificate is currently valid, otherwise false</returns>
		public static bool CertIsValidNow(string certFile)
		{
			// We fudge the subtleties of time validity and invalid format
			int r = X509_CertIsValidNow(certFile, 0);
			return (r == 0);
		}
		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int X509_CertIssuedOn(string strCertFile, StringBuilder sbOutput, int nOutputLen, int flags);
		/// <summary>
		/// Returns date and time certificate was issued
		/// </summary>
		/// <param name="certFile">Filename of certificate file (or its base64 representation)</param>
		/// <returns>Date and time in ISO format or Empty string if error</returns>
		public static string CertIssuedOn(string certFile)
		{
			StringBuilder sb = new StringBuilder(0);
			int n = X509_CertIssuedOn(certFile, sb, 0, 0);
			if (n <= 0) return string.Empty;
			sb = new StringBuilder(n);
			X509_CertIssuedOn(certFile, sb, sb.Capacity, 0);
			return sb.ToString();
		}
		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int X509_CertExpiresOn(string strCertFile, StringBuilder sbOutput, int nOutputLen, int flags);
		/// <summary>
		/// Returns date and time certificate expires
		/// </summary>
		/// <param name="certFile">Filename of certificate file (or its base64 representation)</param>
		/// <returns>Date and time in ISO format or Empty string if error</returns>
		public static string CertExpiresOn(string certFile)
		{
			StringBuilder sb = new StringBuilder(0);
			int n = X509_CertExpiresOn(certFile, sb, 0, 0);
			if (n <= 0) return string.Empty;
			sb = new StringBuilder(n);
			X509_CertExpiresOn(certFile, sb, sb.Capacity, 0);
			return sb.ToString();
		}
		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int X509_CertSerialNumber(string strCertFile, StringBuilder sbOutput, int nOutputLen, int flags);
		/// <summary>
		/// Returns serial number in hex format
		/// </summary>
		/// <param name="certFile">Filename of certificate file (or its base64 representation)</param>
		/// <returns>Serial number in hex format or Empty string if error</returns>
		/// <seealso cref="X509.QueryCert(String, String, X509.Options)"> with query <c>serialNumber</c>.</seealso>>
		public static string CertSerialNumber(string certFile)
		{
			StringBuilder sb = new StringBuilder(0);
			int n = X509_CertSerialNumber(certFile, sb, 0, 0);
			if (n <= 0) return string.Empty;
			sb = new StringBuilder(n);
			X509_CertSerialNumber(certFile, sb, sb.Capacity, 0);
			return sb.ToString();
		}
		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int X509_HashIssuerAndSN(string strCertFile, StringBuilder sbOutput, int nOutputLen, int flags);
		/// <summary>
		/// Creates a message digest of the Issuer's name and the cert serial number
		/// </summary>
		/// <param name="certFile">Filename of certificate file (or its base64 representation)</param>
		/// <param name="algorithm">Hash algorithm to use [default = SHA-1]</param>
		/// <returns>Message digest in hex format or Empty string if error</returns>
		/// <remarks>This (should) give a unique identifier for any certificate</remarks>
		public static string HashIssuerAndSN(string certFile, HashAlgorithm algorithm)
		{
			StringBuilder sb = new StringBuilder(0);
			int n = X509_HashIssuerAndSN(certFile, sb, 0, (int)algorithm);
			if (n <= 0) return string.Empty;
			sb = new StringBuilder(n);
			X509_HashIssuerAndSN(certFile, sb, sb.Capacity, (int)algorithm);
			return sb.ToString();
		}
		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int X509_CertIssuerName(string strCertFile, StringBuilder sbOutput, int nOutputLen, string strDelim, int flags);
		/// <summary>
		/// Return the issuer name of an X.509 certificate
		/// </summary>
		/// <param name="certFile">Filename of certificate file (or its base64 representation)</param>
		/// <param name="delimiter">Optional character for delimiter [Default = semicolon ";"]</param>
		/// <returns>Issuer name or Empty string if error</returns>
		/// <overloads>Return the issuer name</overloads>

		public static string CertIssuerName(string certFile, string delimiter)
		{
			StringBuilder sb = new StringBuilder(0);
			int n = X509_CertIssuerName(certFile, sb, 0, delimiter, 0);
			if (n <= 0) return string.Empty;
			sb = new StringBuilder(n);
			X509_CertIssuerName(certFile, sb, sb.Capacity, delimiter, 0);
			return sb.ToString();
		}
		/// <summary>
		/// Return the issuer name of an X.509 certificate
		/// </summary>
		/// <param name="certFile">Filename of certificate file (or its base64 representation)</param>
		/// <param name="delimiter">Optional character for delimiter [Default = semicolon ";"]</param>
		/// <param name="options">Option, e.g. 
		/// <see cref="X509.Options.Ldap"/> and/or
		/// <see cref="X509.Options.Latin1"/>.
		/// </param>
		/// <returns>Issuer name or Empty string if error</returns>
		public static string CertIssuerName(string certFile, string delimiter, X509.Options options)
		{
			StringBuilder sb = new StringBuilder(0);
			int n = X509_CertIssuerName(certFile, sb, 0, delimiter, (int)options);
			if (n <= 0) return string.Empty;
			sb = new StringBuilder(n);
			X509_CertIssuerName(certFile, sb, sb.Capacity, delimiter, (int)options);
			return sb.ToString();
		}

		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int X509_CertSubjectName(string strCertFile, StringBuilder sbOutput, int nOutputLen, string strDelim, int flags);
		/// <summary>
		/// Gets the subject name of an X.509 certificate
		/// </summary>
		/// <param name="certFile">Filename of certificate file (or its base64 representation)</param>
		/// <param name="delimiter">Optional character for delimiter [Default = semicolon ";"]</param>
		/// <returns>Subject name or Empty string if error</returns>
		/// <overloads>Return the subject name</overloads>
		public static string CertSubjectName(string certFile, string delimiter)
		{
			StringBuilder sb = new StringBuilder(0);
			int n = X509_CertSubjectName(certFile, sb, 0, delimiter, 0);
			if (n <= 0) return string.Empty;
			sb = new StringBuilder(n);
			X509_CertSubjectName(certFile, sb, sb.Capacity, delimiter, 0);
			return sb.ToString();
		}
		/// <summary>
		/// Gets the subject name of an X.509 certificate
		/// </summary>
		/// <param name="certFile">Filename of certificate file (or its base64 representation)</param>
		/// <param name="delimiter">Optional character for delimiter [Default = semicolon ";"]</param>
		/// <param name="options">Option, e.g. 
		/// <see cref="X509.Options.Ldap"/> and/or
		/// <see cref="X509.Options.Latin1"/>.
		/// </param>
		/// <returns>Subject name or Empty string if error</returns>
		public static string CertSubjectName(string certFile, string delimiter, X509.Options options)
		{
			StringBuilder sb = new StringBuilder(0);
			int n = X509_CertSubjectName(certFile, sb, 0, delimiter, (int)options);
			if (n <= 0) return string.Empty;
			sb = new StringBuilder(n);
			X509_CertSubjectName(certFile, sb, sb.Capacity, delimiter, (int)options);
			return sb.ToString();
		}


		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int X509_GetCertFromP7Chain(string strOutputFile, string strP7cFile, int nIndex, int flags);
		/// <summary>
		/// Extracts an X.509 certificate from a PKCS-7 "certs-only" certificate chain file, 
		/// saving the output directly as a new file.
		/// </summary>
		/// <param name="outputFile">Name of output file to be created</param>
		/// <param name="inputFile">Name of the PKCS-7 "certs-only" file</param>
		/// <param name="index">specifying which certificate (1,2,...) in the chain to extract, or 0 to return the count of certificates in the set</param>
		/// <returns>If successful and <c>index</c> is greater than zero, it returns the number of bytes written to the output file, 
		/// which may be zero if no certificate could be found at the given index. 
		/// However, if <c>index</c> is zero, it returns the count of certificates found in the list. 
		/// If an error occurred, it returns a negative <see cref="General.ErrorLookup">error code</see>.</returns>
		/// <remarks>Refer to the manual for further information and remarks on the use of this function.</remarks>
		public static int GetCertFromP7Chain(string outputFile, string inputFile, int index)		
		{
			int r = X509_GetCertFromP7Chain(outputFile, inputFile, index, 0);
			return r;
		}
		
		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int X509_GetCertFromPFX(string strOutputFile, string strPfxFile, string strPassword, int flags);
		/// <summary>
		/// Extracts an X.509 certificate from a PKCS-12 PFX/.p12 file, 
		/// saving the output directly as a new file.
		/// </summary>
		/// <param name="outputFile">Name of output file to be created</param>
		/// <param name="inputFile">Name of the PKCS-12 file</param>
		/// <param name="password">Password or "" if not encrypted</param>
		/// <returns>If successful, it returns the number of bytes written to the output file; 
		/// otherwise it returns a negative <see cref="General.ErrorLookup">error code</see>
		/// </returns>
		/// <remarks>Only supports weak 40-bit RC2 encryption for the certificate.</remarks>
		/// <overloads>Extract X.509 certificate from a PKCS-12 PFX/.p12 file</overloads>
		public static int GetCertFromPFX(string outputFile, string inputFile, string password)		
		{
			int r = X509_GetCertFromPFX(outputFile, inputFile, password, 0);
			return r;
		}
		/// <summary>
		/// Extracts an (unencrypted) X.509 certificate from a PKCS-12 PFX/.p12 file, 
		/// saving the output directly as a new file.
		/// </summary>
		/// <param name="outputFile">Name of output file to be created</param>
		/// <param name="inputFile">Name of the PKCS-12 file</param>
		/// <returns>If successful, it returns the number of bytes written to the output file; 
		/// otherwise it returns a negative <see cref="General.ErrorLookup">error code</see>
		/// </returns>
		public static int GetCertFromPFX(string outputFile, string inputFile)
		{
			int r = X509_GetCertFromPFX(outputFile, inputFile, "", 0);
			return r;
		}

		/// <summary>
		/// Extracts all X.509 certificates from a PKCS-12 PFX/.p12 file, 
		/// saving the output directly as a new PKCS-7 "certs-only" certificate chain file.
		/// </summary>
		/// <param name="outputFile">Name of output file to be created</param>
		/// <param name="inputFile">Name of the PKCS-12 file</param>
		/// <param name="password">Password or "" if not encrypted</param>
		/// <returns>If successful, it returns the number of bytes written to the output file; 
		/// otherwise it returns a negative <see cref="General.ErrorLookup">error code</see>
		/// </returns>
		/// <remarks>Only supports weak 40-bit RC2 encryption for the certificate.</remarks>
		public static int GetP7ChainFromPFX(string outputFile, string inputFile, string password)
		{
			int r = X509_GetCertFromPFX(outputFile, inputFile, password, PKI_PFX_P7CHAIN);
			return r;
		}


		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int X509_ReadStringFromFile(StringBuilder szOutput, int nOutChars, string szCertFile, int nOptions);
		/// <summary>
		/// Creates a base64 string of a X.509 certificate file 
		/// </summary>
		/// <param name="certFile">Filename of certificate file (or its base64 representation)</param>
		/// <returns>String in continuous base64 format, or an empty string on error.</returns>
		public static string ReadStringFromFile(string certFile)
		{
			StringBuilder sb = new StringBuilder(0);
			int n = X509_ReadStringFromFile(sb, 0, certFile, 0);
			if (n <= 0) return string.Empty;
			sb = new StringBuilder(n);
			X509_ReadStringFromFile(sb, sb.Capacity, certFile, 0);
			return sb.ToString();
		}
	
		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int X509_SaveFileFromString(string szNewCertFile, string szCertString, int nOptions);
		/// <summary>
		/// Creates a new X.509 certificate file from a base64 string.
		/// </summary>
		/// <param name="newCertFile">Name of new certificate file to be created.</param>
		/// <param name="certString">String containing certificate data in base64 format.</param>
		/// <param name="inPEMFormat"><c>True</c> to save in base64 PEM format, or <c>false</c> to save in binary DER format.</param>
		/// <returns>Zero if successful or non-zero <see cref="General.ErrorLookup">error code</see></returns>
		/// <remarks>Any existing file of the same name will be overwritten without warning.
		/// <p>A PEM format file will start with <c>-----BEGIN CERTIFICATE-----</c>.</p>
		/// </remarks>
		public static int SaveFileFromString(string newCertFile, string certString, bool inPEMFormat)
		{
			int flags = (int)(inPEMFormat ? X509.Options.FormatPem : X509.Options.FormatBinary);
			int r = X509_SaveFileFromString(newCertFile, certString, flags);
			return r;
		}

		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int X509_KeyUsageFlags(string szCertFile);
		/// <summary>
		/// Returns a bitfield containing the <c>keyUsage</c> flags.
		/// </summary>
		/// <param name="certFile">Filename of certificate file (or its base64 representation)</param>
		/// <returns>If successful, it returns a positive integer containing the <c>keyUsage</c> flags; or 0 if no <c>keyUsage</c> flags are set; otherwise it returns a negative <see cref="General.ErrorLookup">error code</see></returns>
		/// <remarks>See <see cref="X509.KeyUsageOptions"/>.</remarks>
		public static int KeyUsageFlags(string certFile)		
		{
			int r = X509_KeyUsageFlags(certFile);
			return r;
		}

		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int X509_QueryCert(StringBuilder szDataOut, int nOutChars, string szCertFile, string szQuery, int nOptions);

		/// <summary>
		/// Queries an X.509 certificate file for selected information.
		/// </summary>
		/// <param name="certFile">Filename of certificate file (or its base64 representation)</param>
		/// <param name="query">Query string (case insensitive)</param>
		/// <returns>String containing the result, or an empty string on error.</returns>
		/// <remarks>
		/// Both binary BER and base64 PEM-format certificates can be read,
		/// as can a base64 representation of the certificate.
		/// <para>Valid queries are:</para>
		/// <list type="table">
		/// <item>
		/// <term><c>"version"</c></term>
		/// <description>X.509 version number, e.g. <c>"3"</c>.</description>
		/// </item>
		/// <item>
		/// <term><c>"serialNumber"</c></term>
		/// <description>Serial number in hex-encoded format.</description>
		/// </item>
		/// <item>
		/// <term><c>"SigAlgorithm"</c></term>
		/// <description>Signature algorithm used, e.g. <c>"sha1WithRSAEncryption"</c>.</description>
		/// </item>
		/// <item>
		/// <term><c>"sigAlgId"</c></term>
		/// <description>ID of signature algorithm used, see <c>SigAlg_</c> values in <see cref="X509.Options"/>. </description>
		/// </item>
		/// <item>
		/// <term><c>"signatureValue"</c></term>
		/// <description>Signature value in hex-encoded format.</description>
		/// </item>
		/// <item>
		/// <term><c>"notBefore"</c></term>
		/// <description>Date on which the certificate validity period begins in ISO format 
		/// <c>yyyy-mm-ddThh:nn:ssZ</c>
		/// </description>
		/// </item>
		/// <item>
		/// <term><c>"notAfter"</c></term>
		/// <description>Date on which the certificate validity period ends in ISO format 
		/// <c>yyyy-mm-ddThh:nn:ssZ</c>
		/// </description>
		/// </item>
		/// <item>
		/// <term><c>"issuerName"</c></term>
		/// <description>Distinguished name (DN) of entity who has signed and issued the certificate.</description>
		/// </item>
		/// <item>
		/// <term><c>"subjectName"</c></term>
		/// <description>Distinguished name (DN) of the subject.</description>
		/// </item>
		/// <item>
		/// <term><c>"subjectPublicKeyAlgorithm"</c></term>
		/// <description>Algorithm used in subject's public key, e.g. <c>"dsa"</c>.</description>
		/// </item>
		/// <item>
		/// <term><c>"subjectKeyIdentifier"</c></term>
		/// <description>The subject key identifier extension, if present, in hex-encoded format.</description>
		/// </item>
		/// <item>
		/// <term><c>"authorityKeyIdentifier"</c></term>
		/// <description>The authority key identifier extension, if present, in hex-encoded format.</description>
		/// </item>
		/// <item>
		/// <term><c>"rfc822Name"</c></term>
		/// <description>Internet mail address contained in a subjectAltName extension, if present.</description>
		/// </item>
		/// <item>
		/// <term><c>"isCA"</c></term>
		/// <description>Returns <c>"1"</c> if the subject type is a CA, otherwise returns <c>"0"</c>.</description>
		/// </item>
		/// <item>
		/// <term><c>"keyUsageString"</c></term>
		/// <description><c>keyUsage</c> flags in text format, e.g. <c>"digitalSignature,nonRepudiation"</c>.</description>
		/// </item>
		/// <item>
		/// <term><c>"extKeyUsageString"</c></term>
		/// <description><c>extKeyUsage</c> purposes in text format, e.g. <c>"codeSigning,timeStamping"</c>.</description>
		/// </item>
		/// <item>
		/// <term><c>"cRLDistributionPointsURI"</c></term>
		/// <description>First URI found in <c>cRLDistributionPoints</c>, if any.</description>
		/// </item>
		/// <item>
		/// <term><c>"authorityInfoAccessURI"</c></term>
		/// <description>First URI found in <c>authorityInfoAccess</c>, if any.</description>
		/// </item>
		/// </list>
		/// </remarks>
		/// <overloads>Query an X.509 certificate file for selected information</overloads>
		public static string QueryCert(string certFile, string query)	
		{
			return QueryCert(certFile, query, Options.None);
		}

		/// <summary>
		/// Queries an X.509 certificate file for selected information with options.
		/// </summary>
		/// <param name="certFile">Filename of certificate file (or its base64 representation)</param>
		/// <param name="query">Query string (case insensitive)</param>
		/// <param name="options">Option, e.g. <see cref="X509.Options.Latin1"/> or <see cref="X509.Options.Ldap"/></param>
		/// <returns>String containing the result, or an empty string on error.</returns>
		/// <remarks>
		/// <p>Both binary BER and base64 PEM-format certificates can be read,
		/// as can a base64 representation of the certificate.</p>
		/// <p>For a list of valid queries, see the X509.QueryCert(String, String) overload</p>
		///</remarks>
		public static string QueryCert(string certFile, string query, X509.Options options)
		{
			int n;
			int flags = (int)options;
			StringBuilder sb = new StringBuilder(0);

			// X509_QueryCert either returns an integer result directly or sets the string
			n = X509_QueryCert(null, 0, certFile, query, (int)myQuery.PKI_QUERY_GETTYPE);
			if (n == (int)myQuery.PKI_QUERY_STRING)
			{
				n = X509_QueryCert(sb, 0, certFile, query, flags);
				if (n <= 0) return String.Empty;
				sb = new StringBuilder(n);
				X509_QueryCert(sb, sb.Capacity, certFile, query, flags);
			}
			else
			{
				n = X509_QueryCert(sb, 0, certFile, query, flags);
			}
			if (sb.Length == 0)
			{	// Result is an integer returned in n, so set our return value as a string
				sb.Append(n);
			}
			return sb.ToString();
		}

		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int X509_TextDump(string szFileOut, string szCertFile, int nOptions);
		/// <summary>
		/// Dumps details of an X.509 certificate (or a X.509 certificate revocation list (CRL) 
		/// or a PKCS-10 certificate signing request (CSR)) to a text file
		/// </summary>
		/// <param name="outputFile">Filename of text file to be created</param>
		/// <param name="certFile">Filename of certificate file (or its base64 representation)</param>
		/// <returns>If successful, the return value is zero; otherwise it returns a nonzero error code.</returns>
		public static int TextDump(string outputFile, string certFile)
		{
			int r = X509_TextDump(outputFile, certFile, 0);
			return r;
		}

		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int X509_ValidatePath(string szCertListOrP7File, string szTrustedCert, int nOptions);
		/// <summary>
		/// Validates a certificate path
		/// </summary>
		/// <param name="certListOrP7File">either a list of certificate names separated by a semicolon 
		/// or the name of a PKCS-7 "certs-only" file containing the certificates to be validated</param>
		/// <returns>Zero if the certification path is valid;
		/// <see cref="X509.Invalid">X509.Invalid</see> (+1) if the path is invalid; 
		/// otherwise a negative <see cref="General.ErrorLookup">error code</see>.
		/// </returns>
		/// <overloads>Validate a certificate path</overloads>
		public static int ValidatePath(string certListOrP7File)
		{
			int r = X509_ValidatePath(certListOrP7File, "", 0);
			return r;
		}

		/// <summary>
		/// Validates a certificate path
		/// </summary>
		/// <param name="certListOrP7File">either a list of certificate names separated by a semicolon 
		/// or the name of a PKCS-7 "certs-only" file containing the certificates to be validated</param>
		/// <param name="trustedCert">name of the trusted certificate (or base64 representation)</param>
		/// <param name="noTimeCheck">Set True to avoid checking if the certificates are valid now 
		/// [default = check validity dates against system clock].</param>
		/// <returns>Zero if the certification path is valid;
		/// <see cref="X509.Invalid">X509.Invalid</see> (+1) if the path is invalid; 
		/// otherwise a negative <see cref="General.ErrorLookup">error code</see>.
		/// </returns>
		public static int ValidatePath(string certListOrP7File, string trustedCert, bool noTimeCheck)
		{
			int option = (noTimeCheck ? PKI_X509_NO_TIMECHECK : 0);
			int r = X509_ValidatePath(certListOrP7File, trustedCert, option);
			return r;
		}

		/* X509 CRL FUNCTIONS */
		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int X509_MakeCRL(string szCrlFile, string szIssuerCert, string szIssuerKeyFile, 
			string szPassword, string szRevokedCertList, string szExtensions, int nOptions);

		/// <summary>
		/// Creates an X.509 Certificate Revocation List (CRL)
		/// </summary>
		/// <param name="crlFile">name of new CRL file to be created</param>
		/// <param name="issuerCert">name of issuer's X.509 certificate file (or base64 representation)</param>
		/// <param name="issuerKeyFile">name of issuer's encrypted private key file</param>
		/// <param name="password">password for Issuer's encrypted private key file</param>
		/// <param name="revokedCertList">list of revoked certificates in format 
		/// <c>serialNumber,revocationDate; ...</c> or the empty string <c>""</c> 
		/// for no revoked certificates. See the Remarks section below for more details</param>
		/// <param name="extensions">A list of attribute-value pairs separated by semicolons (;)
		/// or the empty string <c>""</c>. Valid attribute-value pairs are:
		/// <list type="bullet">
		/// <item><c>lastUpdate</c>=<i>iso-date-string</i></item>
		/// <item><c>nextUpdate</c>=<i>iso-date-string</i></item>
		/// </list>
		/// </param>
		/// <param name="options">Set as <c>0</c> to choose the default signature algorithm <c>sha1WithRSAEncryption</c>.
		/// To choose another signature algorithm, select one of the <c>SigAlg_</c> options from 
		/// <see cref="X509.Options">X509.Options</see>.
		/// </param>
		/// <returns>If successful, the return value is zero; 
		/// otherwise it returns a non-zero <see cref="General.ErrorLookup">error code</see>.</returns>
		/// <remarks>
		/// This creates a version 1 CRL file with no extensions or cRLReason's.
		/// The parameter <c>revokedCertList</c> must be in the form 
		/// <c>serialNumber,revocationDate;serialNumber,revocationDate; ...</c>.
		/// The serialNumber must either be a positive decimal integer (e.g. <c>123</c>) 
		/// or the number in hex format preceded by #x (e.g. <c>#x0102deadbeef</c>). 
		/// The revocation date must be in ISO date format (e.g. <c>2009-12-31T12:59:59Z</c>). 
		/// For example,
		/// <para>
		/// <c>"1,2007-12-31; 2, 2009-12-31T12:59:59Z; 66000,2066-01-01; #x0102deadbeef,2010-02-28T01:01:59"</c>
		/// </para>
		/// By default, the <c>lastUpdate</c> time in the CRL is set to the time given by the system clock, 
		/// and <c>nextUpdate</c> time is left empty. 
		/// You can specify your own times using the <c>lastUpdate</c> and <c>nextUpdate</c> attributes 
		/// in the extensions parameter. 
		/// Times, if specified, must be in ISO 8601 format and are always interpreted as GMT times whether or not you add a "Z". 
		/// </remarks>
		public static int MakeCRL(string crlFile, string issuerCert,
			string issuerKeyFile, string password, string revokedCertList, string extensions, Options options)
		{
			int r = X509_MakeCRL(crlFile, issuerCert,
				issuerKeyFile, password, revokedCertList, extensions, (int)options);
			return r;
		}

		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int X509_CheckCertInCRL(string szCertFile, string szCrlFile, string szCRLIssuerCert, string szDate, int nOptions);
		/// <summary>
		/// Checks whether an X.509 certificate has been revoked in a Certificate Revocation List (CRL)
		/// </summary>
		/// <param name="certFile">name of X.509 certificate to be checked (or base64 representation)</param>
		/// <param name="crlFile">name of CRL file</param>
		/// <param name="issuerCert">(optional) with name of X.509 certificate file for the entity that issued the CRL (or base64 representation)</param>
		/// <param name="dateStr">(optional) with date in ISO format (<c>yyyy-mm-dd[Thh[:nn:ss]][Z]</c>) on or after 
		/// you wish to check for revocation. Leave empty ""  for any date. 
		/// The time must be in GMT (UTC, Zulu time)</param>
		/// <returns>Zero if the certificate is NOT in the CRL; 
		/// <see cref="X509.Revoked">X509.Revoked</see> (+1) if the certificate has been revoked; 
		/// otherwise an <see cref="General.ErrorLookup">error code</see>.
		/// </returns>
		/// <remarks>
		/// The optional <c>dateStr</c> parameter allows you check 
		/// whether a certificate was revoked only after the given date-time, which must be GMT (UTC).
		/// If the optional <c>issuerCert</c> is specified, the signature of the CRL will be checked
		/// against the key in the issuer's certificate and
		/// a SIGNATURE_ERROR will result if the signature is invalid. 
		/// </remarks>
		/// <seealso cref="X509.VerifyCert"/>
		/// <seealso cref="X509.CertIsValidNow"/>
		public static int CheckCertInCRL(string certFile, string crlFile, string issuerCert, string dateStr)
		{
			int r = X509_CheckCertInCRL(certFile, crlFile, issuerCert, dateStr, 0);
			return r;
		}
	}

	/// <summary>
	/// Online Certificate Status Protocol (OCSP)
	/// </summary>
	public class Ocsp
	{
		private Ocsp()
		{}	// Static methods only, so hide constructor.

		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int OCSP_MakeRequest(StringBuilder szOutput, int nOutChars, string szIssuerCert, string szCertFileOrSerialNum, string szExtensions, int nOptions);
		/// <summary>
		/// Create an Online Certification Status Protocol (OCSP) request as a base64 string. 
		/// </summary>
		/// <param name="issuerCert">name of issuer's X.509 certificate file (or base64 representation)</param>
		/// <param name="certFileOrSerialNumber">either the name of X.509 certificate file to be checked or its serial number in hexadecimal format preceded by #x</param>
		/// <param name="hashAlg">Hash algorithm to be used [default = SHA-1]</param>
		/// <returns>A base64 string suitable for an OCSP request to an Online Certificate Status Manager or an empty string on error.</returns>
		/// <remarks>The issuer's X.509 certficate must be specified. 
		/// The certificate to be checked can either be specified directly as a filename 
		/// or as a serialNumber in hexadecimal format preceded by "#x", e.g. "#x01deadbeef". 
		/// If the latter format is used, it must be in hexadecimal format, 
		/// so the serial number 10 would be passed as "#x0a". 
		/// It is an error (NO_MATCH_ERROR) if the issuer's name of the certificate to be checked 
		/// does not match the subject name of the issuer's certificate.
		/// </remarks>
		public static string MakeRequest(string issuerCert, string certFileOrSerialNumber, HashAlgorithm hashAlg)
		{
			StringBuilder sb = new StringBuilder(0);
			int n = OCSP_MakeRequest(sb, 0, issuerCert, certFileOrSerialNumber, "", (int)hashAlg);
			if (n <= 0) return string.Empty;
			sb = new StringBuilder(n);
			OCSP_MakeRequest(sb, sb.Capacity, issuerCert, certFileOrSerialNumber, "", (int)hashAlg);
			return sb.ToString();
		}
		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int OCSP_ReadResponse(StringBuilder szOutput, int nOutChars, string szResponseFile, string szIssuerCert, string szExtensions, int nOptions);
		/// <summary>
		/// Read a response to an Online Certification Status Protocol (OCSP) request and outputs the main results in text form.
		/// </summary>
		/// <param name="responseFile">name of the file containing the response data in BER format.</param>
		/// <param name="issuerCert">(optional) name of issuer's X.509 certificate file (or base64 representation)</param>
		/// <returns>A text string outlining the main results in the response data or an empty string on error.</returns>
		/// <remarks>Note that a revoked certificate will still result in a "Successful response", so check the CertStatus. 
		/// The issuer's X.509 certficate <c>issuerCert</c> is optional. 
		/// If provided, it will be used to check the signature on the OCSP reponse and and an error 
		/// will result if the signature is not valid. 
		/// <b>CAUTION:</b> For some CAs (e.g. VeriSign) the key used to sign the OCSP response is not the same as 
		/// the key in the issuer's certificate, so specifying the issuer's certificate in this case will result 
		/// in a signature error. If you can separately obtain the certificate used to sign the OCSP response, 
		/// then specify this as the <c>issuerCert</c>; otherwise leave as the empty string <c>""</c>.
		/// </remarks>
		public static string ReadResponse(string responseFile, string issuerCert)
		{
			StringBuilder sb = new StringBuilder(0);
			int n = OCSP_ReadResponse(sb, 0, responseFile, issuerCert, "", 0);
			if (n <= 0) return string.Empty;
			sb = new StringBuilder(n);
			OCSP_ReadResponse(sb, sb.Capacity, responseFile, issuerCert, "", 0);
			return sb.ToString();
	   }
	}


	/// <summary>
	/// Triple DES Cipher (3DES, TDEA) [deprecated:
	/// use Cipher() class with CipherAlgorithm.Tdea instead]
	/// </summary>
	public class Tdea
	{
		private Tdea()
		{}	// Static methods only, so hide constructor.

		/// <summary>
		/// Block size in bytes
		/// </summary>
		public const int BlockSize = 8;

		/* TRIPLE DES FUNCTIONS */
		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int TDEA_HexMode(StringBuilder output, string input,
			string strHexKey, int bEncrypt, string strMode, string sHexIV);
		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int TDEA_B64Mode(StringBuilder output, string input,
			string strB64Key, int bEncrypt, string strMode, string sB64IV);
		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int TDEA_BytesMode(byte[] output, byte[] input,
			int nbytes, byte[] key, 
			int bEncrypt, string strMode, byte[] iv);
		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int TDEA_File(string strFileOut, string strFileIn,
			byte[] key, int bEncrypt,
			string strMode, byte[] iv);

		/// <summary>
		/// Encrypt data in byte array
		/// </summary>
		/// <param name="input">Input data</param>
		/// <param name="key">Key of exactly 24 bytes (192 bits)</param>
		/// <param name="mode">Cipher Mode</param>
		/// <param name="iv">IV of exactly 8 bytes or <c>null</c> for ECB mode</param>
		/// <returns>Ciphertext in byte array or empty array on error</returns>
		/// <remarks>For ECB and CBC modes, input data length <b>must</b> be an exact multiple of the block length</remarks>
		/// <overloads>Encrypt data</overloads>
		public static byte[] Encrypt(byte[] input, byte[] key, Mode mode, byte[] iv)
		{
			string strMode = MyInternals.ModeString(mode);
			byte[] b = new byte[input.Length];
			int r = TDEA_BytesMode(b, input, input.Length, key, (int)Direction.Encrypt, strMode, iv);
			if (r != 0)
				b = new byte[0];
			return b;
		}

		/// <summary>
		/// Decrypt data in byte array
		/// </summary>
		/// <param name="input">Input data</param>
		/// <param name="key">Key of exactly 24 bytes (192 bits)</param>
		/// <param name="mode">Cipher Mode</param>
		/// <param name="iv">IV of exactly 8 bytes or <c>null</c> for ECB mode</param>
		/// <returns>Decrypted data in byte array or empty array on error</returns>
		/// <remarks>For ECB and CBC modes, input data length <b>must</b> be an exact multiple of the block length</remarks>
		/// <overloads>Decrypt data</overloads>
		public static byte[] Decrypt(byte[] input, byte[] key, Mode mode, byte[] iv)
		{
			string strMode = MyInternals.ModeString(mode);
			byte[] b = new byte[input.Length];
			int r = TDEA_BytesMode(b, input, input.Length, key, (int)Direction.Decrypt, strMode, iv);
			if (r != 0)
				b = new byte[0];
			return b;
		}

		/// <summary>
		/// Encrypt hex-encoded data string
		/// </summary>
		/// <param name="inputHex">Hex-encoded input data</param>
		/// <param name="keyHex">Hex-encoded key representing exactly 24 bytes (192 bits)</param>
		/// <param name="mode">Cipher Mode</param>
		/// <param name="ivHex">Hex-encoded IV representing exactly 8 bytes or <c>""</c> for ECB mode</param>
		/// <returns>Ciphertext in hex-encoded string or empty string on error</returns>
		/// <remarks>For ECB and CBC modes, the length of the decoded input bytes <b>must</b> be an exact multiple of the block length</remarks>
		public static string Encrypt(string inputHex, string keyHex, Mode mode, string ivHex)
		{
			string strMode = MyInternals.ModeString(mode);
			StringBuilder sb = new StringBuilder(inputHex.Length);
			int r = TDEA_HexMode(sb, inputHex, keyHex, (int)Direction.Encrypt, strMode, ivHex);
			if (r != 0) return String.Empty;
			return sb.ToString();
		}

		/// <summary>
		/// Decrypt hex-encoded data string
		/// </summary>
		/// <param name="inputHex">Hex-encoded input data</param>
		/// <param name="keyHex">Hex-encoded key representing exactly 24 bytes (192 bits)</param>
		/// <param name="mode">Cipher Mode</param>
		/// <param name="ivHex">Hex-encoded IV representing exactly 8 bytes or <c>""</c> for ECB mode</param>
		/// <returns>Decrypted data in hex-encoded string or empty string on error</returns>
		/// <remarks>For ECB and CBC modes, the length of the decoded input bytes <b>must</b> be an exact multiple of the block length</remarks>
		public static string Decrypt(string inputHex, string keyHex, Mode mode, string ivHex)
		{
			string strMode = MyInternals.ModeString(mode);
			StringBuilder sb = new StringBuilder(inputHex.Length);
			int r = TDEA_HexMode(sb, inputHex, keyHex, (int)Direction.Decrypt, strMode, ivHex);
			if (r != 0) return String.Empty;
			return sb.ToString();
		}

		/// <summary>
		/// Encrypt encoded data string
		/// </summary>
		/// <param name="inputStr">Encoded input data</param>
		/// <param name="keyStr">Encoded key representing exactly 24 bytes (192 bits)</param>
		/// <param name="mode">Cipher Mode</param>
		/// <param name="ivStr">Encoded IV representing exactly 8 bytes or <c>""</c> for ECB mode</param>
		/// <param name="encodingBase">Type of encoding used </param>
		/// <returns>Ciphertext in hex-encoded string or empty string on error</returns>
		/// <remarks>For ECB and CBC modes, the length of the decoded input bytes <b>must</b> be an exact multiple of the block length</remarks>
		public static string Encrypt(string inputStr, string keyStr, Mode mode, string ivStr, EncodingBase encodingBase)
		{
			string strMode = MyInternals.ModeString(mode);
			StringBuilder sb = new StringBuilder(inputStr.Length);
			int r = -999;
			switch(encodingBase)
			{
				case EncodingBase.Base16:
					r = TDEA_HexMode(sb, inputStr, keyStr, (int)Direction.Encrypt, strMode, ivStr);
					break;
				case EncodingBase.Base64:
					r = TDEA_B64Mode(sb, inputStr, keyStr, (int)Direction.Encrypt, strMode, ivStr);
					break;
			}
			if (r != 0) return String.Empty;
			return sb.ToString();
		}

		/// <summary>
		/// Decrypt encoded data string
		/// </summary>
		/// <param name="inputStr">Encoded input data</param>
		/// <param name="keyStr">Encoded key representing exactly 24 bytes (192 bits)</param>
		/// <param name="mode">Cipher Mode</param>
		/// <param name="ivStr">Encoded IV representing exactly 8 bytes or <c>""</c> for ECB mode</param>
		/// <param name="encodingBase">Type of encoding used </param>
		/// <returns>Decrypted data in encoded string or empty string on error</returns>
		/// <remarks>For ECB and CBC modes, the length of the decoded input bytes <b>must</b> be an exact multiple of the block length</remarks>
		public static string Decrypt(string inputStr, string keyStr, Mode mode, string ivStr, EncodingBase encodingBase)
		{
			string strMode = MyInternals.ModeString(mode);
			StringBuilder sb = new StringBuilder(inputStr.Length);
			int r = -999;
			switch(encodingBase)
			{
				case EncodingBase.Base16:
					r = TDEA_HexMode(sb, inputStr, keyStr, (int)Direction.Decrypt, strMode, ivStr);
					break;
				case EncodingBase.Base64:
					r = TDEA_B64Mode(sb, inputStr, keyStr, (int)Direction.Decrypt, strMode, ivStr);
					break;
			}
			if (r != 0) return String.Empty;
			return sb.ToString();
		}

		/// <summary>
		/// Encrypt a file
		/// </summary>
		/// <param name="fileOut">Name of output file to be created or overwritten</param>
		/// <param name="fileIn">Name of input file</param>
		/// <param name="key">Key of exactly 24 bytes (192 bits)</param>
		/// <param name="mode">Cipher Mode</param>
		/// <param name="iv">IV of exactly 8 bytes or <c>null</c> for ECB mode</param>
		/// <returns>0 if successful or non-zero <see cref="General.ErrorLookup">error code</see></returns>
		/// <remarks><c>fileOut</c> and <c>fileIn</c> must <b>not</b> be the same</remarks>
		/// <overloads>Encrypt a file</overloads>
		public static int FileEncrypt(string fileOut, string fileIn, byte[] key, 
			Mode mode, byte[] iv)
		{
			string strMode = MyInternals.ModeString(mode);
			return TDEA_File(fileOut, fileIn, key, (int)Direction.Encrypt, strMode, iv);
		}
		/// <summary>
		/// Decrypt a file
		/// </summary>
		/// <param name="fileOut">Name of output file to be created or overwritten</param>
		/// <param name="fileIn">Name of input file</param>
		/// <param name="key">Key of exactly 8 bytes (64 bits)</param>
		/// <param name="mode">Cipher Mode</param>
		/// <param name="iv">IV of exactly 8 bytes or <c>null</c> for ECB mode</param>
		/// <returns>0 if successful or non-zero <see cref="General.ErrorLookup">error code</see></returns>
		/// <remarks><c>fileOut</c> and <c>fileIn</c> must <b>not</b> be the same</remarks>
		/// <overloads>Decrypt a file</overloads>
		public static int FileDecrypt(string fileOut, string fileIn, byte[] key, 
			Mode mode, byte[] iv)
		{
			string strMode = MyInternals.ModeString(mode);
			return TDEA_File(fileOut, fileIn, key, (int)Direction.Decrypt, strMode, iv);
		}

		/// <summary>
		/// Encrypt a file passing key and IV as hex strings
		/// </summary>
		/// <param name="fileOut">Name of output file to be created or overwritten</param>
		/// <param name="fileIn">Name of input file</param>
		/// <param name="keyHex">Hex-encoded key of exact length</param>
		/// <param name="mode">Cipher Mode</param>
		/// <param name="ivHex">Hex-encoded IV or <c>""</c> for ECB mode</param>
		/// <returns>0 if successful or non-zero <see cref="General.ErrorLookup">error code</see></returns>
		/// <remarks><c>fileOut</c> and <c>fileIn</c> must <b>not</b> be the same.
		/// The output file is in binary format.</remarks>
		public static int FileEncrypt(string fileOut, string fileIn, string keyHex, 
			Mode mode, string ivHex)
		{
			string strMode = MyInternals.ModeString(mode);
			return TDEA_File(fileOut, fileIn, Cnv.FromHex(keyHex), (int)Direction.Encrypt, strMode, Cnv.FromHex(ivHex));
		}
		/// <summary>
		/// Decrypt a file passing key and IV as hex strings
		/// </summary>
		/// <param name="fileOut">Name of output file to be created or overwritten</param>
		/// <param name="fileIn">Name of input file</param>
		/// <param name="keyHex">Hex-encoded key of exact length</param>
		/// <param name="mode">Cipher Mode</param>
		/// <param name="ivHex">Hex-encoded IV or <c>""</c> for ECB mode</param>
		/// <returns>0 if successful or non-zero <see cref="General.ErrorLookup">error code</see></returns>
		/// <remarks><c>fileOut</c> and <c>fileIn</c> must <b>not</b> be the same.
		/// The output file is in binary format.</remarks>
		public static int FileDecrypt(string fileOut, string fileIn, string keyHex, 
			Mode mode, string ivHex)
		{
			string strMode = MyInternals.ModeString(mode);
			return TDEA_File(fileOut, fileIn, Cnv.FromHex(keyHex), (int)Direction.Decrypt, strMode, Cnv.FromHex(ivHex));
		}
	}

	/// <summary>
	/// Generic Block Cipher
	/// </summary>
	public class Cipher
	{
		private Cipher()
		{}	// Static methods only, so hide constructor.

		/// <summary>
		/// Advanced options
		/// </summary>
		[Flags]
		public enum Opts
		{
			/// <summary>
			/// Default options
			/// </summary>
			Default = 0,
			/// <summary>
			/// Prefix (prepend) the IV before the ciphertext in the output file (ignored for ECB mode)
			/// </summary>
			PrefixIV = 0x1000,
		}

		/// <summary>
		/// Return the block size in bytes for a given cipher algorithm
		/// </summary>
		/// <param name="alg">Cipher algorithm</param>
		/// <returns>Block size in bytes</returns>
		public static int BlockBytes(CipherAlgorithm alg)
		{
			return MyInternals.BlockSize(alg);
		}

		/// <summary>
		/// Return the key size in bytes for a given cipher algorithm
		/// </summary>
		/// <param name="alg">Cipher algorithm</param>
		/// <returns>Key size in bytes</returns>
		public static int KeyBytes(CipherAlgorithm alg)
		{
			return MyInternals.KeySize(alg);
		}

		/* GENERIC BLOCK CIPHER FUNCTIONS */
		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int CIPHER_Bytes(int fEncrypt, byte[] output, byte[] input, int nbytes, 
			byte[] key, byte[] iv, string algAndMode, int options);
		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int CIPHER_Hex(int fEncrypt, StringBuilder output, int outlen, string input,
			string strHexKey, string sHexIV, string algAndMode, int options);
		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int CIPHER_File(int fEncrypt, string strFileOut, string strFileIn, 
			byte[] key, byte[] iv, string algAndMode, int options);

		// Added in [v11.1]

		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int CIPHER_EncryptBytes2(byte[] lpOutput, int nOutBytes, byte[] lpInput, int nInputLen, byte[] lpKey, int nKeyLen, byte[] lpIV, int nIvLen, string szAlgModePad, int nOptions);
		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int CIPHER_DecryptBytes2(byte[] lpOutput, int nOutBytes, byte[] lpInput, int nInputLen, byte[] lpKey, int nKeyLen, byte[] lpIV, int nIvLen, string szAlgModePad, int nOptions);
		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int CIPHER_FileEncrypt(string szFileOut, string szFileIn, byte[] lpKey, int nKeyLen, byte[] lpIV, int nIvLen, string szAlgModePad, int nOptions);
		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int CIPHER_FileDecrypt(string szFileOut, string szFileIn, byte[] lpKey, int nKeyLen, byte[] lpIV, int nIvLen, string szAlgModePad, int nOptions);

		
		/// <summary>
		/// Encrypt data in byte array 
		/// </summary>
		/// <param name="input">Input data to be encrypted</param>
		/// <param name="key">Key of exact length for block cipher algorithm</param>
		/// <param name="iv">Initialization Vector (IV) of exactly the block size or <c>null</c> for ECB mode</param>
		/// <param name="cipherAlg">Cipher algorithm</param>
		/// <param name="mode">Cipher mode</param>
		/// <returns>Ciphertext in byte array or empty array on error</returns>
		/// <remarks>For ECB and CBC modes, input data length <b>must</b> be an exact multiple of the block length</remarks>
		public static byte[] Encrypt(byte[] input, byte[] key, byte[] iv, CipherAlgorithm cipherAlg, Mode mode)
		{
			byte[] b = new byte[input.Length];
			int flags = (int)cipherAlg | (int)mode | (int)Padding.NoPad;
			int ivlen = (iv == null ? 0 : iv.Length);
			// [v11.1] Replaced "CIPHER_Bytes" with "CIPHER_EncryptBytes2" NB Return value now +ve
			int r = CIPHER_EncryptBytes2(b, b.Length, input, input.Length, key, key.Length, iv, ivlen, "", flags);
			if (r < 0)
				b = new byte[0];
			return b;
		}

		/// <summary>
		/// Decrypt data in byte array 
		/// </summary>
		/// <param name="input">Input data to be decrypted</param>
		/// <param name="key">Key of exact length for block cipher algorithm</param>
		/// <param name="iv">Initialization Vector (IV) of exactly the block size or <c>null</c> for ECB mode</param>
		/// <param name="cipherAlg">Cipher algorithm</param>
		/// <param name="mode">Cipher mode</param>
		/// <returns>Decrypted data in byte array or empty array on error</returns>
		/// <remarks>For ECB and CBC modes, input data length <b>must</b> be an exact multiple of the block length</remarks>
		public static byte[] Decrypt(byte[] input, byte[] key, byte[] iv, CipherAlgorithm cipherAlg, Mode mode)
		{
			byte[] b = new byte[input.Length];
			int flags = (int)cipherAlg | (int)mode | (int)Padding.NoPad;
			int ivlen = (iv == null ? 0 : iv.Length);
			// [v11.1] Replaced "CIPHER_Bytes" with "CIPHER_DecryptBytes2" NB Return value now +ve
			int r = CIPHER_DecryptBytes2(b, b.Length, input, input.Length, key, key.Length, iv, ivlen, "", flags);
			if (r < 0)
				b = new byte[0];
			return b;
		}

		/// <summary>
		/// Encrypt hex-encoded data string
		/// </summary>
		/// <param name="inputHex">Hex-encoded input data</param>
		/// <param name="keyHex">Hex-encoded key representing exact key length</param>
		/// <param name="ivHex">Hex-encoded IV representing exact block length or <c>""</c> for ECB mode</param>
		/// <param name="cipherAlg">Cipher algorithm</param>
		/// <param name="mode">Cipher mode</param>
		/// <returns>Ciphertext in hex-encoded string or empty string on error</returns>
		/// <remarks>For ECB and CBC modes, input data length <b>must</b> be an exact multiple of the block length</remarks>
		public static string Encrypt(string inputHex, string keyHex, string ivHex, CipherAlgorithm cipherAlg, Mode mode)
		{
			StringBuilder sb = new StringBuilder(inputHex.Length);
			int flags = (int)cipherAlg | (int)mode;
			int r = CIPHER_Hex((int)Direction.Encrypt, sb, sb.Length, inputHex, keyHex, ivHex, "", flags);
			if (r != 0) return String.Empty;
			return sb.ToString();
		}

		/// <summary>
		/// Decrypt hex-encoded data string
		/// </summary>
		/// <param name="inputHex">Hex-encoded input data</param>
		/// <param name="keyHex">Hex-encoded key representing exact key length</param>
		/// <param name="ivHex">Hex-encoded IV representing exact block length or <c>""</c> for ECB mode</param>
		/// <param name="cipherAlg">Cipher Algorithm</param>
		/// <param name="mode">Cipher Mode</param>
		/// <returns>Decrypted plaintext in hex-encoded string or empty string on error</returns>
		/// <remarks>For ECB and CBC modes, input data length <b>must</b> represent an exact multiple of the block length</remarks>
		public static string Decrypt(string inputHex, string keyHex, string ivHex, CipherAlgorithm cipherAlg, Mode mode)
		{
			StringBuilder sb = new StringBuilder(inputHex.Length);
			int flags = (int)cipherAlg | (int)mode;
			int r = CIPHER_Hex((int)Direction.Decrypt, sb, sb.Length, inputHex, keyHex, ivHex, "", flags);
			if (r != 0) return String.Empty;
			return sb.ToString();
		}

		/* BLOCK CIPHER WITH ALGORITHM/MODE/PADDING */

		/// <summary>
		/// Encrypts data in a byte array using the specified block cipher algorithm, mode and padding.
		/// </summary>
		/// <param name="input">Input data to be encrypted</param>
		/// <param name="key">Key of exact length for block cipher algorithm</param>
		/// <param name="iv">Initialization Vector (IV) of exactly the block size or <c>null</c> for ECB mode</param>
		/// <param name="cipherAlg">Cipher algorithm</param>
		/// <param name="mode">Cipher mode</param>
		/// <param name="pad">Padding method to use</param>
		/// <returns>Ciphertext in byte array or empty array on error</returns>
		/// <remarks>Default padding is <c>Pkcs5</c> for ECB and CBC mode and
		/// <c>NoPad</c> for all other modes.</remarks>
		/// <overloads>Encrypt data.</overloads>
		public static byte[] Encrypt(byte[] input, byte[] key, byte[] iv, CipherAlgorithm cipherAlg, Mode mode, Padding pad)
		{
			int flags = (int)cipherAlg | (int)mode | (int)pad;
			byte[] b;
			// [v11.1] Replaced "CIPHER_EncryptBytesPad" with "CIPHER_EncryptBytes2"
			int ivlen = (iv == null ? 0 : iv.Length);
			int n = CIPHER_EncryptBytes2(null, 0, input, input.Length, key, key.Length, iv, ivlen, "", flags);
			if (n > 0) {
				b = new byte[n];
				n = CIPHER_EncryptBytes2(b, b.Length, input, input.Length, key, key.Length, iv, ivlen, "", flags);
			}
			else {
				b = new byte[0];
			}
			return b;
		}

		/// <summary>
		/// Decrypts data in a byte array using the specified block cipher algorithm, mode and padding.
		/// </summary>
		/// <param name="input">Input data to be decrypted</param>
		/// <param name="key">Key of exact length for block cipher algorithm</param>
		/// <param name="iv">Initialization Vector (IV) of exactly the block size or <c>null</c> for ECB mode</param>
		/// <param name="cipherAlg">Cipher algorithm</param>
		/// <param name="mode">Cipher mode</param>
		/// <param name="pad">Padding method to use</param>
		/// <returns>Decrypted plaintext in byte array or empty array on error</returns>
		/// <remarks>Default padding is <c>Pkcs5</c> for ECB and CBC mode and
		/// <c>NoPad</c> for all other modes.
		/// It is an error if the specified padding is not found after decryption.</remarks>
		/// <overloads>Decrypt data.</overloads>
		public static byte[] Decrypt(byte[] input, byte[] key, byte[] iv, CipherAlgorithm cipherAlg, Mode mode, Padding pad)
		{
			int flags = (int)cipherAlg | (int)mode | (int)pad;
			byte[] b = new byte[input.Length];
			// [v11.1] Replaced "CIPHER_DecryptBytesPad" with "CIPHER_DecryptBytes2"
			int ivlen = (iv == null ? 0 : iv.Length);
			int n = CIPHER_DecryptBytes2(b, b.Length, input, input.Length, key, key.Length, iv, ivlen, "", flags);
			if (n > 0) {
				if (n < b.Length) {
					// Copy larger array to smaller one of correct length
					byte[] b1 = new byte[n];
					Array.Copy(b, b1, n);
					b = b1;
				}
			}
			else {
				b = new byte[0];
			}
			return b;
		}

		/// <summary>
		/// Encrypt a file
		/// </summary>
		/// <param name="fileOut">Name of output file to be created or overwritten</param>
		/// <param name="fileIn">Name of input file</param>
		/// <param name="key">Key of of exact length for block cipher algorithm</param>
		/// <param name="iv">Initialization Vector (IV) of exactly the block size or <c>null</c> for ECB mode</param>
		/// <param name="cipherAlg">Cipher Algorithm</param>
		/// <param name="mode">Cipher Mode</param>
		/// <returns>0 if successful or non-zero <see cref="General.ErrorLookup">error code</see></returns>
		/// <remarks><c>fileOut</c> and <c>fileIn</c> must <b>not</b> be the same</remarks>
		/// <overloads>Encrypt a file.</overloads>
		public static int FileEncrypt(string fileOut, string fileIn, byte[] key, 
			byte[] iv, CipherAlgorithm cipherAlg, Mode mode)
		{
			int flags = (int)cipherAlg | (int)mode;
			int ivlen = (iv == null ? 0 : iv.Length);
			// [v11.1] Replaced "CIPHER_File(ENCRYPT)" with "CIPHER_FileEncrypt"
			return CIPHER_FileEncrypt(fileOut, fileIn, key, key.Length, iv, iv.Length, null, flags);
		}

		/// <summary>
		/// Decrypt a file
		/// </summary>
		/// <param name="fileOut">Name of output file to be created or overwritten</param>
		/// <param name="fileIn">Name of input file</param>
		/// <param name="key">Key of of exact length for block cipher algorithm</param>
		/// <param name="iv">Initialization Vector (IV) of exactly the block size or <c>null</c> for ECB mode</param>
		/// <param name="cipherAlg">Cipher Algorithm</param>
		/// <param name="mode">Cipher Mode</param>
		/// <returns>0 if successful or non-zero <see cref="General.ErrorLookup">error code</see></returns>
		/// <remarks><c>fileOut</c> and <c>fileIn</c> must <b>not</b> be the same</remarks>
		/// <overloads>Decrypt a file.</overloads>
		public static int FileDecrypt(string fileOut, string fileIn, byte[] key,
			byte[] iv, CipherAlgorithm cipherAlg, Mode mode)
		{
			int flags = (int)cipherAlg | (int)mode;
			int ivlen = (iv == null ? 0 : iv.Length);
			// [v11.1] Replaced "CIPHER_File(DECRYPT)" with "CIPHER_FileDecrypt"
			return CIPHER_FileDecrypt(fileOut, fileIn, key, key.Length, iv, iv.Length, null, flags);
		}

		/* NEW IN [v11.1]: ENCRYPT/DECRYPT A FILE WITH SPECIFIED PADDING */

		/// <summary>
		/// Encrypt a file with specified padding
		/// </summary>
		/// <param name="fileOut">Name of output file to be created or overwritten</param>
		/// <param name="fileIn">Name of input file</param>
		/// <param name="key">Key of of exact length for block cipher algorithm</param>
		/// <param name="iv">Initialization Vector (IV) of exactly the block size or <c>null</c> for ECB mode</param>
		/// <param name="cipherAlg">Cipher Algorithm</param>
		/// <param name="mode">Cipher Mode</param>
		/// <param name="pad">Padding method to use (ECB and CBC modes only)</param>
		/// <param name="opts">Advanced options</param>
		/// <returns>0 if successful or non-zero <see cref="General.ErrorLookup">error code</see></returns>
		/// <remarks><c>fileOut</c> and <c>fileIn</c> must <b>not</b> be the same</remarks>
		public static int FileEncrypt(string fileOut, string fileIn, byte[] key,
			byte[] iv, CipherAlgorithm cipherAlg, Mode mode, Padding pad, Opts opts)
		{
			int flags = (int)cipherAlg | (int)mode | (int)pad | (int)opts;
			int ivlen = (iv == null ? 0 : iv.Length);
			return CIPHER_FileEncrypt(fileOut, fileIn, key, key.Length, iv, ivlen, null, flags);
		}
		/// <summary>
		/// Decrypt a file with specified padding
		/// </summary>
		/// <param name="fileOut">Name of output file to be created or overwritten</param>
		/// <param name="fileIn">Name of input file</param>
		/// <param name="key">Key of of exact length for block cipher algorithm</param>
		/// <param name="iv">Initialization Vector (IV) of exactly the block size or <c>null</c> for ECB mode</param>
		/// <param name="cipherAlg">Cipher Algorithm</param>
		/// <param name="mode">Cipher Mode</param>
		/// <param name="pad">Padding method to use (ECB and CBC modes only)</param>
		/// <param name="opts">Advanced options</param>
		/// <returns>0 if successful or non-zero <see cref="General.ErrorLookup">error code</see></returns>
		/// <remarks><c>fileOut</c> and <c>fileIn</c> must <b>not</b> be the same</remarks>
		public static int FileDecrypt(string fileOut, string fileIn, byte[] key,
			byte[] iv, CipherAlgorithm cipherAlg, Mode mode, Padding pad, Opts opts)
		{
			int flags = (int)cipherAlg | (int)mode | (int)pad | (int)opts;
			int ivlen = (iv == null ? 0 : iv.Length);
			return CIPHER_FileDecrypt(fileOut, fileIn, key, key.Length, iv, ivlen, null, flags);
		}

		/// <summary>
		/// Encrypt a file passing key and IV as hex strings
		/// </summary>
		/// <param name="fileOut">Name of output file to be created or overwritten</param>
		/// <param name="fileIn">Name of input file containing binary data</param>
		/// <param name="keyHex">Hex-encoded key of exact length</param>
		/// <param name="ivHex">Hex-encoded IV or <c>""</c> for ECB mode</param>
		/// <param name="cipherAlg">Cipher Algorithm</param>
		/// <param name="mode">Cipher Mode</param>
		/// <returns>0 if successful or non-zero <see cref="General.ErrorLookup">error code</see></returns>
		/// <remarks><c>fileOut</c> and <c>fileIn</c> must <b>not</b> be the same.
		/// The output file is in binary format, automatically padded with PKCS5 padding if required.</remarks>
		public static int FileEncrypt(string fileOut, string fileIn, string keyHex, 
			string ivHex, CipherAlgorithm cipherAlg, Mode mode)
		{
			int flags = (int)cipherAlg | (int)mode;
			byte[] key = Cnv.FromHex(keyHex);
			byte[] iv = Cnv.FromHex(ivHex);
			// [v11.1] Replaced "CIPHER_File(ENCRYPT)" with "CIPHER_FileEncrypt"
			int r = CIPHER_FileEncrypt(fileOut, fileIn, key, key.Length, iv, iv.Length, null, flags);
			Wipe.Data(key);
			return r;
		}

		/// <summary>
		/// Decrypt a file passing key and IV as hex strings
		/// </summary>
		/// <param name="fileOut">Name of output file to be created or overwritten</param>
		/// <param name="fileIn">Name of input file, in binary format, padded with PKCS5 padding if required.</param>
		/// <param name="keyHex">Hex-encoded key of exact length</param>
		/// <param name="ivHex">Hex-encoded IV or <c>""</c> for ECB mode</param>
		/// <param name="cipherAlg">Cipher Algorithm</param>
		/// <param name="mode">Cipher Mode</param>
		/// <returns>0 if successful or non-zero <see cref="General.ErrorLookup">error code</see></returns>
		/// <remarks><c>fileOut</c> and <c>fileIn</c> must <b>not</b> be the same.
		/// The output file is in binary format.</remarks>
		public static int FileDecrypt(string fileOut, string fileIn, string keyHex, 
			string ivHex, CipherAlgorithm cipherAlg, Mode mode)
		{
			int flags = (int)cipherAlg | (int)mode;
			byte[] key = Cnv.FromHex(keyHex);
			byte[] iv = Cnv.FromHex(ivHex);
			// [v11.1] Replaced "CIPHER_File(DECRYPT)" with "CIPHER_FileDecrypt"
			int r = CIPHER_FileDecrypt(fileOut, fileIn, key, key.Length, iv, iv.Length, null, flags);
			Wipe.Data(key);
			return r;
		}

		/* KEY WRAP USING BLOCK CIPHER */

		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int CIPHER_KeyWrap(byte[] output, int nOutBytes, byte[] data, int nDataLen, 
			byte[] kek, int nKekLen, int options);
		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int CIPHER_KeyUnwrap(byte[] output, int nOutBytes, byte[] data, int nDataLen, 
			byte[] kek, int nKekLen, int options);

		/// <summary>
		/// Wraps (encrypts) key material with a key-encryption key
		/// </summary>
		/// <param name="data">Key material to be wrapped</param>
		/// <param name="kek">Key encryption key</param>
		/// <param name="cipherAlg">Block cipher to use for wrapping</param>
		/// <returns>Wrapped key (or empty array on error)</returns>
		public static byte[] KeyWrap(byte[] data, byte[] kek, CipherAlgorithm cipherAlg)
		{
			int flags = (int)cipherAlg;
			byte[] b;
			int len = CIPHER_KeyWrap(null, 0, data, data.Length, kek, kek.Length, flags);
			if (len <= 0) return new byte[0];
			b = new byte[len];
			len = CIPHER_KeyWrap(b, b.Length, data, data.Length, kek, kek.Length, flags);
			if (len <= 0)
				b = new byte[0];
			return b;
		}
		/// <summary>
		/// Unwraps (decrypts) key material with a key-encryption key
		/// </summary>
		/// <param name="data">Wrapped key</param>
		/// <param name="kek">Key encryption key</param>
		/// <param name="cipherAlg">Block cipher to use for wrapping</param>
		/// <returns>Unwrapped key material (or empty array on error)</returns>
		public static byte[] KeyUnwrap(byte[] data, byte[] kek, CipherAlgorithm cipherAlg)
		{
			int flags = (int)cipherAlg;
			byte[] b;
			int len = CIPHER_KeyUnwrap(null, 0, data, data.Length, kek, kek.Length, flags);
			if (len <= 0) return new byte[0];
			b = new byte[len];
			len = CIPHER_KeyUnwrap(b, b.Length, data, data.Length, kek, kek.Length, flags);
			if (len <= 0)
				b = new byte[0];
			return b;
		}

		/* PADDING FOR BLOCK CIPHER */
		/// <summary>
		/// Pad byte array to correct length for ECB and CBC encryption
		/// </summary>
		/// <param name="input">data to be padded</param>
		/// <param name="cipherAlg">Block cipher being used</param>
		/// <returns>padded data in byte array</returns>
		/// <remarks>Uses PKCS#5 method of padding</remarks>
		/// <overloads>Pad data to correct length for ECB and CBC encryption</overloads>		
		public static byte[] Pad(byte[] input, CipherAlgorithm cipherAlg)
		{
			return MyInternals.Pad(input, MyInternals.BlockSize(cipherAlg), Padding.Pkcs5);
		}
		/// <summary>
		/// Pad byte array for block cipher 
		/// </summary>
		/// <param name="input">data to be padded</param>
		/// <param name="cipherAlg">Block cipher being used</param>
		/// <param name="pad">Padding method to use</param>
		/// <returns>padded data in byte array</returns>
		public static byte[] Pad(byte[] input, CipherAlgorithm cipherAlg, Padding pad)
		{
			return MyInternals.Pad(input, MyInternals.BlockSize(cipherAlg), pad);
		}
		/// <summary>
		/// Pad hex-encoded string to correct length for ECB and CBC encryption
		/// </summary>
		/// <param name="inputHex">hex-encoded data to be padded</param>
		/// <param name="cipherAlg">Block cipher being used</param>
		/// <returns>padded data in hex-encoded string</returns>
		/// <remarks>Uses PKCS#5 method of padding</remarks>
		public static string Pad(string inputHex, CipherAlgorithm cipherAlg)
		{
			return MyInternals.Pad(inputHex, MyInternals.BlockSize(cipherAlg), Padding.Pkcs5);
		}
		/// <summary>
		/// Pads hex-encoded string for block cipher
		/// </summary>
		/// <param name="inputHex">hex-encoded data to be padded</param>
		/// <param name="cipherAlg">Block cipher being used</param>
		/// <param name="pad">Padding method to use</param>
		/// <returns>padded data in hex-encoded string</returns>
		public static string Pad(string inputHex, CipherAlgorithm cipherAlg, Padding pad)
		{
			return MyInternals.Pad(inputHex, MyInternals.BlockSize(cipherAlg), pad);
		}
		/// <summary>
		/// Remove padding from an encryption block
		/// </summary>
		/// <param name="input">padded data</param>
		/// <param name="cipherAlg">Block cipher being used</param>
		/// <returns>Unpadded data in byte array or unchanged data on error</returns>
		/// <remarks>Padding is expected according to the convention in PKCS#5.
		/// The unpadded output is <em>always</em> shorter than the padded input.
		/// An error is indicated by returning the <em>original</em> data.
		/// Check its length.
		/// </remarks>
		/// <overloads>Remove padding from an encryption block</overloads>		
		public static byte[] Unpad(byte[] input, CipherAlgorithm cipherAlg)
		{
			return MyInternals.Unpad(input, MyInternals.BlockSize(cipherAlg), Padding.Pkcs5);
		}
		/// <summary>
		/// Remove padding from an encryption block
		/// </summary>
		/// <param name="input">padded data</param>
		/// <param name="cipherAlg">Block cipher being used</param>
		/// <param name="pad">Padding method to use</param>
		/// <returns>Unpadded data in byte array.</returns>
		/// <remarks>Unless <c>pad</c> is <c>NoPad</c>, the 
		/// unpadded output is <em>always</em> shorter than the padded input.
		/// An error is indicated by returning the <em>original</em> data.
		/// </remarks>
		public static byte[] Unpad(byte[] input, CipherAlgorithm cipherAlg, Padding pad)
		{
			return MyInternals.Unpad(input, MyInternals.BlockSize(cipherAlg), pad);
		}
		/// <summary>
		/// Remove padding from a hex-encoded encryption block 
		/// </summary>
		/// <param name="inputHex">hex-encoded padded data</param>
		/// <param name="cipherAlg">Block cipher being used</param>
		/// <returns>Unpadded data in hex-encoded string or unchanged data on error</returns>
		/// <remarks>Padding is expected according to the convention in PKCS#5. 
		/// The unpadded output is <em>always</em> shorter than the padded input.
		/// An error is indicated by returning the <em>original</em> data.
		/// Check its length.
		/// </remarks>
		public static string Unpad(string inputHex, CipherAlgorithm cipherAlg)
		{
			return MyInternals.Unpad(inputHex, MyInternals.BlockSize(cipherAlg), Padding.Pkcs5);
		}
		/// <summary>
		/// Remove padding from a hex-encoded encryption block
		/// </summary>
		/// <param name="inputHex">hex-encoded padded data</param>
		/// <param name="cipherAlg">Block cipher being used</param>
		/// <param name="pad">Padding method to use</param>
		/// <returns>Unpadded data in hex-encoded string.</returns>
		/// <remarks>Unless <c>pad</c> is <c>NoPad</c>, the 
		/// unpadded output is <em>always</em> shorter than the padded input.
		/// An error is indicated by returning the <em>original</em> data.
		/// </remarks>
		public static string Unpad(string inputHex, CipherAlgorithm cipherAlg, Padding pad)
		{
			return MyInternals.Unpad(inputHex, MyInternals.BlockSize(cipherAlg), pad);
		}
	}


	/// <summary>
	/// Message Digest Hash Functions
	/// </summary>
	public class Hash
	{
		private Hash()
		{}	// Static methods only, so hide constructor.

		private const int PKI_HASH_MODE_TEXT = 0x10000;
		private const int PKI_HASH_DOUBLE    = 0x20000;

		/* MESSAGE DIGEST HASH FUNCTIONS */
		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int HASH_HexFromBytes(StringBuilder sbHexDigest, int digLen,  byte[] aMessage, int messageLen, int flags);
		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int HASH_HexFromFile(StringBuilder sbHexDigest, int digLen, string strFileName, int flags);
		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int HASH_Bytes(byte[] digest, int digLen, byte[] aMessage, int messageLen, int flags);
		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int HASH_HexFromHex(StringBuilder sbHexDigest, int digLen,  string strMessageHex, int flags);

		/// <summary>
		/// Creates hash digest in byte format of byte input
		/// </summary>
		/// <param name="message">Message data in byte format</param>
		/// <param name="hashAlg">Hash algorithm to be used</param>
		/// <returns>Message digest in byte format</returns>
		public static byte[] BytesFromBytes(byte[] message, HashAlgorithm hashAlg)
		{
			// [2007-02-27] Replace PKI_MAX_HASH_BYTES with actual length
			byte[] digest = new byte[MyInternals.HashBytes(hashAlg)];
			HASH_Bytes(digest, digest.Length, message, message.Length, (int)hashAlg);
			return digest;
		}
		/// <summary>
		/// Creates hash digest in hex format of byte input
		/// </summary>
		/// <param name="message">Message data in byte format</param>
		/// <param name="hashAlg">Hash algorithm to be used</param>
		/// <returns>Message digest in hex-encoded format</returns>
		public static string HexFromBytes(byte[] message, HashAlgorithm hashAlg)
		{
			StringBuilder sb = new StringBuilder((int)HashLen.PKI_MAX_HASH_CHARS);
			HASH_HexFromBytes(sb, sb.Capacity, message, message.Length, (int)hashAlg);
			return sb.ToString();
		}
		/// <summary>
		/// Creates hash digest in hex format of string input
		/// </summary>
		/// <param name="message">Message data string</param>
		/// <param name="hashAlg">Hash algorithm to be used</param>
		/// <returns>Message digest in hex-encoded format</returns>
		public static string HexFromString(string message, HashAlgorithm hashAlg)
		{
			StringBuilder sb = new StringBuilder((int)HashLen.PKI_MAX_HASH_CHARS);
			byte[] b = System.Text.Encoding.Default.GetBytes(message);
			HASH_HexFromBytes(sb, sb.Capacity, b, b.Length, (int)hashAlg);
			return sb.ToString();
		}
		/// <summary>
		/// Creates hash digest in hex format of hex-encoded input
		/// </summary>
		/// <param name="messageHex">Message data in hex-encoded format</param>
		/// <param name="hashAlg">Hash algorithm to be used</param>
		/// <returns>Message digest in hex-encoded format</returns>
		public static string HexFromHex(string messageHex, HashAlgorithm hashAlg)
		{
			StringBuilder sb = new StringBuilder((int)HashLen.PKI_MAX_HASH_CHARS);
			HASH_HexFromHex(sb, sb.Capacity, messageHex, (int)hashAlg);
			return sb.ToString();
		}

		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int HASH_File(byte[] digest, int digLen, string strFileName, int flags);
		/// <summary>
		/// Creates hash digest of a binary file
		/// </summary>
		/// <param name="fileName">Name of file containing message data</param>
		/// <param name="hashAlg">Hash algorithm to be used</param>
		/// <returns>Message digest in byte format</returns>
		public static byte[] BytesFromFile(string fileName, HashAlgorithm hashAlg)
		{
			// [2007-02-27] Replace PKI_MAX_HASH_BYTES with actual length
			byte[] digest = new byte[MyInternals.HashBytes(hashAlg)];
			HASH_File(digest, digest.Length, fileName, (int)hashAlg);
			return digest;
		}
		/// <summary>
		/// Creates hash digest in hex format of a binary file
		/// </summary>
		/// <param name="fileName">Name of file containing message data</param>
		/// <param name="hashAlg">Hash algorithm to be used</param>
		/// <returns>Message digest in hex-encoded format</returns>
		public static string HexFromFile(string fileName, HashAlgorithm hashAlg)
		{
			StringBuilder sb = new StringBuilder((int)HashLen.PKI_MAX_HASH_CHARS);
			HASH_HexFromFile(sb, sb.Capacity, fileName, (int)hashAlg);
			return sb.ToString();
		}
		/// <summary>
		/// Creates hash digest in hex format of a text file, treating CR-LF (0x13, 0x10) pairs as a single LF (0x10)
		/// </summary>
		/// <param name="fileName">Name of file containing message data</param>
		/// <param name="hashAlg">Hash algorithm to be used</param>
		/// <returns>Message digest in hex format</returns>
		/// <remarks>This <em>should</em> give the same message digest of a text file on both Unix and Windows systems.</remarks>
		public static string HexFromTextFile(string fileName, HashAlgorithm hashAlg)
		{
			StringBuilder sb = new StringBuilder((int)HashLen.PKI_MAX_HASH_CHARS);
			HASH_HexFromFile(sb, sb.Capacity, fileName, (int)hashAlg | PKI_HASH_MODE_TEXT);
			return sb.ToString();
		}
		/// <summary>
		/// Creates double hash, i.e. hash of hash, in byte format of byte input
		/// </summary>
		/// <param name="message">Message data in byte format</param>
		/// <param name="hashAlg">Hash algorithm to be used</param>
		/// <returns>Message digest <c>HASH(HASH(m))</c> in byte format</returns>
		public static byte[] Double(byte[] message, HashAlgorithm hashAlg)
		{
			byte[] digest = new byte[MyInternals.HashBytes(hashAlg)];
			HASH_Bytes(digest, digest.Length, message, message.Length, (int)hashAlg|PKI_HASH_DOUBLE);
			return digest;
		}
	}

	/// <summary>
	/// Keyed-hash based message authentication code (HMAC) functions
	/// </summary>
	public class Hmac
	{
		private Hmac()
		{}	// Static methods only, so hide constructor.

		/* HMAC FUNCTIONS */
		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int HMAC_Bytes(byte[] digest, int digLen, byte[] lpMessage, int messageLen, byte[] lpKey, int keyLen, int flags);
		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int HMAC_HexFromBytes(StringBuilder szHexDigest, int nOutChars, byte[] lpMessage, int messageLen, byte[] lpKey, int keyLen, int flags);
		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int HMAC_HexFromHex(StringBuilder sbHexDigest, int digLen, string szMessageHex, string szKeyHex, int flags);

		/// <summary>
		/// Creates a keyed-hash HMAC in byte format from byte input
		/// </summary>
		/// <param name="message">Message to be signed in byte format</param>
		/// <param name="key">Key in byte format</param>
		/// <param name="hashAlg">Hash algorithm to be used</param>
		/// <returns>HMAC in byte format</returns>
		public static byte[] BytesFromBytes(byte[] message, byte[] key, HashAlgorithm hashAlg)
		{
			byte[] digest = new byte[MyInternals.HashBytes(hashAlg)];
			HMAC_Bytes(digest, digest.Length, message, message.Length, key, key.Length, (int)hashAlg);
			return digest;
		}
		/// <summary>
		/// Creates a keyed-hash HMAC in hex-encoded format from byte input
		/// 
		/// </summary>
		/// <param name="message">Message to be signed in byte format</param>
		/// <param name="key">Key in byte format</param>
		/// <param name="hashAlg">Hash algorithm to be used</param>
		/// <returns>HMAC in hex-encoded format</returns>
		public static string HexFromBytes(byte[] message, byte[] key, HashAlgorithm hashAlg)
		{
			StringBuilder sb = new StringBuilder((int)HashLen.PKI_MAX_HASH_CHARS);
			HMAC_HexFromBytes(sb, sb.Capacity, message, message.Length, key, key.Length, (int)hashAlg);
			return sb.ToString();
		}

		/// <summary>
		/// Creates a keyed-hash HMAC in hex-encoded format from hex-encoded input
		/// </summary>
		/// <param name="messageHex">Message to be signed in hex-encoded format</param>
		/// <param name="keyHex">Key in hex-encoded format</param>
		/// <param name="hashAlg">Hash algorithm to be used</param>
		/// <returns>HMAC in hex-encoded format</returns>
		public static string HexFromHex(string messageHex, string keyHex, HashAlgorithm hashAlg)
		{
			StringBuilder sb = new StringBuilder((int)HashLen.PKI_MAX_HASH_CHARS);
			HMAC_HexFromHex(sb, sb.Capacity, messageHex, keyHex, (int)hashAlg);
			return sb.ToString();
		}

	}

	/// <summary>
	/// Data Wiping Functions
	/// </summary>
	public class Wipe
	{
		private Wipe()
		{}	// Static methods only, so hide constructor.

		/* MISC UTILITIES */
		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int WIPE_File(string strFileName, int flags);
		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int WIPE_Data(byte[] lpData, int datalen);
		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi,EntryPoint="WIPE_Data")]
		static extern int WIPE_String(StringBuilder lpData, int datalen);

		// NB You can't use this to wipe a C# string.

		/// <summary>
		/// Securely wipes and deletes a file using 7-pass DOD standards
		/// </summary>
		/// <param name="fileName">Name of file to be wiped</param>
		/// <returns><c>true</c> if successful; <c>false</c> if fails</returns>
		public static bool File(string fileName)
		{
			int r = WIPE_File(fileName, 0);
			return (r == 0);
		}
		/// <summary>
		/// Zeroises data in memory
		/// </summary>
		/// <param name="data">data to be wiped</param>
		/// <returns><c>true</c> if successful; <c>false</c> if fails</returns>
		public static bool Data(byte[] data)
		{
			int r = WIPE_Data(data, data.Length);
			return (r == 0);
		}
		/// <summary>
		/// Zeroises a StringBuilder
		/// </summary>
		/// <param name="sb">StringBuilder to be wiped</param>
		/// <returns><c>true</c> if successful; <c>false</c> if fails</returns>
		/// <remarks>NB You can't wipe an ordinary string as they are immutable in C#,
		/// so store any sensitive string data in a StringBuilder.</remarks>
		public static bool String(StringBuilder sb)
		{
			int r = WIPE_String(sb, sb.Capacity);
			return (r == 0);
		}
	}
		
	/// <summary>
	/// Random Number Generator to NIST SP800-90
	/// </summary>
	public class Rng
	{
		private Rng()
		{}	// Static methods only, so hide constructor.

		private const int PKI_RNG_SEED_BYTES = 64;
		/// <summary>
		/// Required size for RNG seed file
		/// </summary>
		public const int SeedFileSize = PKI_RNG_SEED_BYTES;

		/// <summary>
		/// Required security strength for user-prompted entropy
		/// </summary>
		public enum Strength
		{
			/// <summary>
			/// Default option
			/// </summary>
			Default = 0x00,
			/// <summary>
			/// 112 bits of security (default)
			/// </summary>
			Bits_112 = 0x00,
			/// <summary>
			/// 128 bits of security
			/// </summary>
			Bits_128 = 0x01,
		}
		
		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int RNG_Bytes(byte[] output, int out_len, byte[] seed, int seedlen);
		/// <summary>
		/// Generate an array of random bytes
		/// </summary>
		/// <param name="numBytes">Required number of random bytes</param>
		/// <returns>Array of random bytes</returns>
		/// <overloads>Generates an array of random bytes</overloads>
		public static byte[] Bytes(int numBytes)
		{
			byte[] b = new byte[numBytes];
			RNG_Bytes(b, b.Length, null, 0);
			return b;
		}
		/// <summary>
		/// Generate an array of random bytes with user-supplied entropy
		/// </summary>
		/// <param name="numBytes">Required number of random bytes</param>
		/// <param name="arrSeed">User-supplied entropy in byte format</param>
		/// <returns>Array of random bytes</returns>
		public static byte[] Bytes(int numBytes, byte[] arrSeed)
		{
			byte[] b = new byte[numBytes];
			RNG_Bytes(b, b.Length, arrSeed, 0);
			return b;
		}

		/// <summary>
		/// Generate an array of random bytes with user-supplied entropy
		/// </summary>
		/// <param name="numBytes">Required number of random bytes</param>
		/// <param name="seedStr">User-supplied entropy in string format</param>
		/// <returns>Array of random bytes</returns>
		public static byte[] Bytes(int numBytes, string seedStr)
		{
			byte[] b = new byte[numBytes];
			byte[] arrSeed = System.Text.Encoding.Default.GetBytes(seedStr);
			RNG_Bytes(b, b.Length, arrSeed, 0);
			return b;
		}

		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int RNG_BytesWithPrompt(byte[] lpOutput, int nOutputLen, string szPrompt, int nOptions);
		/// <summary>
		/// Generate an array of random bytes with a prompt for keyboard input
		/// </summary>
		/// <param name="numBytes">Required number of random bytes</param>
		/// <returns>Array of random bytes</returns>
		/// <overloads>Generates an array of random bytes with a prompt for keyboard input</overloads>
		public static byte[] BytesWithPrompt(int numBytes)
		{
			byte[] b = new byte[numBytes];
			RNG_BytesWithPrompt(b, b.Length, "", 0);
			return b;
		}
		/// <summary>
		/// Generate a random set of byte data with a prompt to enter random keystrokes.
		/// </summary>
		/// <param name="numBytes">Required number of random bytes</param>
		/// <param name="prompt">Alternative prompt. Set as an empty string <c>""</c> for the default prompt.</param>
		/// <param name="strength">Estimated security strength</param>
		/// <returns>Array of random bytes</returns>
		public static byte[] BytesWithPrompt(int numBytes, string prompt, Strength strength)
		{
			byte[] b = new byte[numBytes];
			int flags = (int)strength;
			RNG_BytesWithPrompt(b, b.Length, prompt, flags);
			return b;
		}

		/// <summary>
		/// Generate a single random octet (byte)
		/// </summary>
		/// <returns>Single byte value randomly chosen between 0 and 255</returns>
		public static byte Octet()
		{
			byte[] b = new byte[1];
			RNG_Bytes(b, b.Length, null, 0);
			return b[0];
		}

		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int RNG_Number(int lower, int upper);
		/// <summary>
		/// Generate a random number (integer) in a given range
		/// </summary>
		/// <param name="lower">lower value of range</param>
		/// <param name="upper">upper value of range</param>
		/// <returns>Random integer x: lower &lt;= x &lt;= upper</returns>
		public static int Number(int lower, int upper)
		{
			return RNG_Number(lower, upper);
		}

		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int RNG_Initialize(string seedFile, int nOptions);
		/// <summary>
		/// Initialize the RNG generator with a seed file.
		/// </summary>
		/// <param name="seedFile">Full path name of seed file</param>
		/// <returns><c>true</c> if successful; <c>false</c> if fails</returns>
		/// <remarks>If the seed file does not exist, it will be created.</remarks>
		public static bool Initialize(string seedFile)
		{
			int r;
			r = RNG_Initialize(seedFile, 0);
			return (r == 0);
		}

		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int RNG_MakeSeedFile(string seedFile, string prompt, int nOptions);
		/// <summary>
		/// Create a new seed file suitable for use with Rng.Initialize
		/// </summary>
		/// <param name="seedFile">Name of seed file to be created</param>
		/// <returns><c>true</c> if successful; <c>false</c> if fails</returns>
		/// <remarks>Any existing file will be overwritten.</remarks>
		public static bool MakeSeedFile(string seedFile)
		{
			int r;
			r = RNG_MakeSeedFile(seedFile, "", 0);
			return (r == 0);
		}

		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int RNG_UpdateSeedFile(string szSeedFile, int nOptions);
		/// <summary>
		/// Update the RNG seed file
		/// </summary>
		/// <param name="seedFile">Full path name of seed file</param>
		/// <returns><c>true</c> if successful; <c>false</c> if fails</returns>
		/// <remarks>The seed file must exist and be writable.</remarks>
		public static bool UpdateSeedFile(string seedFile)
		{
			int r;
			r = RNG_UpdateSeedFile(seedFile, 0);
			return (r == 0);
		}

		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int RNG_Test(string szFileName, int nOptions);
		/// <summary>
		/// Carry out a NIST SP800-90 health check and FIPS140-2 statistical tests on the random number generator
		/// </summary>
		/// <param name="resultFile">Name of results file to be created, 
		/// or <c>null</c> not to create a results file.</param>
		/// <returns><c>true</c> if successful; <c>false</c> if fails</returns>
		/// <remarks>Any existing file will be overwritten.</remarks>
		public static bool Test(string resultFile)
		{
			int r;
			r = RNG_Test(resultFile, 0);
			return (r == 0);
		}

	}

	/// <summary>
	/// Password Dialog Functions
	/// </summary>
	public class Pwd
	{
		private Pwd()
		{}	// Static methods only, so hide constructor.

		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int PWD_Prompt(StringBuilder sbPassword, int nPwdLen, string strCaption);
		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int PWD_PromptEx(StringBuilder sbPassword, int nPwdLen, string strCaption, string strPrompt, int flags);
		/// <summary>
		/// Opens a dialog box to receive a password
		/// </summary>
		/// <param name="maxChars">Maximum characters expected in password</param>
		/// <param name="caption">Caption for dialog window</param>
		/// <returns>String containing password or Empty string if user cancels</returns>
		/// <overloads>Opens a dialog box to receive a password.</overloads>
		public static string Prompt(int maxChars, string caption)
		{
			StringBuilder sb = new StringBuilder(maxChars);
			int r = PWD_Prompt(sb, sb.Capacity, caption);
			if (r < 0)
				return string.Empty;
			return sb.ToString();
		}
		/// <summary>
		/// Opens a dialog box to receive a password
		/// </summary>
		/// <param name="maxChars">Maximum characters expected in password</param>
		/// <param name="caption">Caption for dialog window</param>
		/// <param name="prompt">Wording for prompt</param>
		/// <returns>String containing password or Empty string if user cancels</returns>
		public static string Prompt(int maxChars, string caption, string prompt)
		{
			StringBuilder sb = new StringBuilder(maxChars);
			int r = PWD_PromptEx(sb, sb.Capacity, caption, prompt, 0);
			if (r < 0)
				return string.Empty;
			return sb.ToString();
		}
	}

	/// <summary>
	/// PEM file conversion routines
	/// </summary>
	public class Pem
	{
		private Pem()
		{ }	// Static methods only, so hide constructor.

		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int PEM_FileFromBinFileEx(string szOutputFile, string szFileIn, string szHeader, int nLineLen, int nOptions);
		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int PEM_FileToBinFile(string szOutputFile, string szFileIn);

		/// <overloads>Create a PEM file from a binary file.</overloads>
		/// <summary>
		/// Create a PEM file from a binary file.
		/// </summary>
		/// <param name="fileToMake">Name of PEM file to create</param>
		/// <param name="fileIn">Name of input binary file</param>
		/// <param name="header">Header to be used. Leave empty to omit the PEM header and footer.</param>
		/// <param name="lineLen">Maximum length of a line in the resulting PEM file [default = 64 characters]</param>
		/// <returns>Zero if successful; otherwise it returns an <see cref="General.ErrorLookup">error code</see></returns>
		/// <remarks><em>Any</em> input file is accepted and treated as binary data. 
		/// No checks are made that the header matches the data.</remarks>
		public static int FileFromBinFile(string fileToMake, string fileIn, string header, int lineLen)
		{
			int r = PEM_FileFromBinFileEx(fileToMake, fileIn, header, lineLen, 0);
			return r;
		}

		/// <summary>
		/// Create a PEM file from a binary file with option for line endings.
		/// </summary>
		/// <param name="fileToMake">Name of PEM file to create</param>
		/// <param name="fileIn">Name of input binary file</param>
		/// <param name="header">Header to be used. Leave empty to omit the PEM header and footer.</param>
		/// <param name="lineLen">Maximum length of a line in the resulting PEM file [default = 64 characters]</param>
		/// <param name="unixEOL">Set true for Unix/SSL LF line endings [default = Windows CR-LF endings]</param>
		/// <returns>Zero if successful; otherwise it returns an <see cref="General.ErrorLookup">error code</see></returns>
		public static int FileFromBinFile(string fileToMake, string fileIn, string header, int lineLen, bool unixEOL)
		{
			int PKI_KEY_FORMAT_SSL = 0x20000;
			int opts = (unixEOL ? PKI_KEY_FORMAT_SSL : 0);
			int r = PEM_FileFromBinFileEx(fileToMake, fileIn, header, lineLen, opts);
			return r;
		}
		
		/// <summary>
		/// Convert the contents of a PEM file into a binary file.
		/// </summary>
		/// <param name="fileToMake">Name of binary file to create.</param>
		/// <param name="fileIn">Name of input PEM file</param>
		/// <returns>Zero if successful; otherwise it returns an <see cref="General.ErrorLookup">error code</see></returns>
		public static int FileToBinFile(string fileToMake, string fileIn)
		{
			int r = PEM_FileToBinFile(fileToMake, fileIn);
			return r;
		}
	}

	/// <summary>
	/// Password-based encryption
	/// </summary>
	 public class Pbe
	{
		private Pbe()
		{ }	// Static methods only, so hide constructor.

		// PASSWORD-BASED ENCRYPTION PROTOTYPES
		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int PBE_Kdf2(byte[] dk, int dkLen, byte[] pwd, int pwdLen,
			byte[] salt, int saltLen, int count, int nOptions);
		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int PBE_Kdf2Hex(StringBuilder sbhexstr, int maxchars, int dkLen, string pwd,
			string saltHex, int count, int nOptions);

		///<overloads>Four overloads: two for bytes, two for hex; one of each with option to specify HMAC algorithm</overloads>		
		/// <summary>
		/// Derive a key of any length from a password using the PBKDF2 algorithm from PKCS #5 v2.1.
		/// </summary>
		/// <param name="dkLen">Required length of key in bytes</param>
		/// <param name="pwdBytes">Password in byte format</param>
		/// <param name="salt">Salt in byte format</param>
		/// <param name="count">Iteration count</param>
		/// <returns>Key in byte[] format</returns>
		/// <remarks>Defaults to HMAC-SHA-1 algorithm for PRF</remarks>
		public static byte[] Kdf2(int dkLen, byte[] pwdBytes, byte[] salt, int count)
		{
			byte[] b = new byte[dkLen];
			int r = PBE_Kdf2(b, dkLen, pwdBytes, pwdBytes.Length, salt, salt.Length, count, 0);
			if (r != 0)
				return new byte[0];
			return b;
		}

		/// <summary>
		/// Derive a key of any length from a password using the PBKDF2 algorithm using specified HMAC algorithm.
		/// </summary>
		/// <param name="dkLen">Required length of key in bytes</param>
		/// <param name="pwdBytes">Password in byte format</param>
		/// <param name="salt">Salt in byte format</param>
		/// <param name="count">Iteration count</param>
		/// <param name="hashAlg">Hash algorithm to use in HMAC PRF</param>
		/// <returns>Key in byte[] format</returns>
		public static byte[] Kdf2(int dkLen, byte[] pwdBytes, byte[] salt, int count, HashAlgorithm hashAlg)
		{
			byte[] b = new byte[dkLen];
			int r = PBE_Kdf2(b, dkLen, pwdBytes, pwdBytes.Length, salt, salt.Length, count, (int)hashAlg);
			if (r != 0)
				return new byte[0];
			return b;
		}

		/// <summary>
		/// Derive a key in hex format of any length from a password with the salt in hex format.
		/// </summary>
		/// <param name="dkLen">Required length of key in bytes</param>
		/// <param name="pwdStr">Password</param>
		/// <param name="saltHex">Salt in hex format</param>
		/// <param name="count">Iteration count</param>
		/// <returns>Key in hex format</returns>
		/// <remarks>The password is passed as normal text; the salt in hex format</remarks>
		/// <example><code>
		/// string keyHex = Pbe.Kdf2(24, "password", "78578e5a5d63cb06", 2048);
		/// </code></example>
		public static string Kdf2(int dkLen, string pwdStr, string saltHex, int count)
		{
			int nchars = dkLen * 2;
			StringBuilder sb = new StringBuilder(nchars);
			PBE_Kdf2Hex(sb, nchars, dkLen, pwdStr, saltHex, count, 0);
			return sb.ToString();
		}

		/// <summary>
		/// Derive a key in hex format of any length from a password with the salt in hex format using specified HMAC algorithm.
		/// </summary>
		/// <param name="dkLen">Required length of key in bytes</param>
		/// <param name="pwdStr">Password</param>
		/// <param name="saltHex">Salt in hex format</param>
		/// <param name="count">Iteration count</param>
		/// <param name="hashAlg">Hash algorithm to use in HMAC PRF</param>
		/// <returns>Key in hex format</returns>
		public static string Kdf2(int dkLen, string pwdStr, string saltHex, int count, HashAlgorithm hashAlg)
		{
			int nchars = dkLen * 2;
			StringBuilder sb = new StringBuilder(nchars);
			PBE_Kdf2Hex(sb, nchars, dkLen, pwdStr, saltHex, count, (int)hashAlg);
			return sb.ToString();
		}
	}

	/// <summary>
	/// ASN.1 utilities
	/// </summary>
	public class Asn1
	{
		private Asn1()
		{ }	// Static methods only, so hide constructor.


		private const int PKI_ASN1_NOCOMMENTS = 0x100000;
		private const int PKI_ASN1_ADDLEVELS = 0x800000;
		private const int PKI_ASN1_TYPE_MAXCHARS = 64;

		/// <summary>
		/// Options for ASN.1 methods
		/// </summary>
		[Flags()]
		public enum Options
		{
			/// <summary>
			/// Default options
			/// </summary>
			Default = 0,
			/// <summary>
			/// Hide the comments [default=show comments]
			/// </summary>
			NoComments = PKI_ASN1_NOCOMMENTS,
			/// <summary>
			/// Show level numbers [default=hide level numbers]
			/// </summary>
			AddLevels = PKI_ASN1_ADDLEVELS,
		 }

		// ASN.1 UTILITIES
		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int ASN1_TextDump(string szFileOut, string szFileOrPEMString, int nOptions);

		/// <summary>
		/// Dump details of an ASN.1 formatted data file to a text file.
		/// </summary>
		/// <param name="outputFile">Filename of text file to be created</param>
		/// <param name="fileOrPEMString">Filename of ASN.1 formatted data file to be analyzed (or a string containing its base64 representation)</param>
		/// <returns>Zero if successful; otherwise it returns an <see cref="General.ErrorLookup">error code</see></returns>
		public static int TextDump(string outputFile, string fileOrPEMString)
		{
			int r = ASN1_TextDump(outputFile, fileOrPEMString, 0);
			return r;
		}
		/// <summary>
		/// Dump details of an ASN.1 formatted data file to a text file (with options).
		/// </summary>
		/// <param name="outputFile">Filename of text file to be created</param>
		/// <param name="fileOrPEMString">Filename of ASN.1 formatted data file to be analyzed (or a string containing its base64 or PEM representation)</param>
		/// <param name="options">Option flags: set as zero for defaults.</param>
		/// <returns>Zero if successful; otherwise it returns an <see cref="General.ErrorLookup">error code</see></returns>
		public static int TextDump(string outputFile, string fileOrPEMString, Asn1.Options options)
		{
			int r = ASN1_TextDump(outputFile, fileOrPEMString, (int)options);
			return r;
		}

		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int ASN1_Type(StringBuilder szOutput, int nOutChars, string szFileOrPEMString, int nOptions);
		
		/// <summary>
		/// Describe the type of ASN.1 data.
		/// </summary>
		/// <param name="fileOrPEMString">Filename of ASN.1 formatted data file to be analyzed (or a string containing its base64 or PEM representation)</param>
		/// <returns>String containing the name of the type of ASN.1 data or the empty string if not found</returns>
		public static string Type(string fileOrPEMString)
		{
			StringBuilder sb = new StringBuilder(PKI_ASN1_TYPE_MAXCHARS);
			int r = ASN1_Type(sb, sb.Capacity, fileOrPEMString, 0);
			if (r <= 0) return "";
			return sb.ToString();
		}
	}

	/// <summary>
	/// S/MIME utilities
	/// </summary>
	public class Smime
	{
		private Smime()
		{ }	// Static methods only, so hide constructor.

		/// <summary>
		/// Options for S/MIME methods
		/// </summary>
		[Flags()]
		public enum Options
		{
			/// <summary>
			/// Default options
			/// </summary>
			Default = 0,
			/// <summary>
			/// Encode output in base64
			/// </summary>
			EncodeBase64 = 0x10000,
			/// <summary>
			/// Encode body in binary encoding
			/// </summary>
			EncodeBinary = 0x20000,
			/// <summary>
			/// Add an "x-" to the content subtype (for compatibility with legacy applications)
			/// </summary>
			AddX = 0x100000,
		}

		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int SMIME_Wrap(string szFileOut, string szFileIn, string szFeatures, int nOptions);

		/// <summary>
		/// Wrap a CMS object in an S/MIME entity.
		/// </summary>
		/// <param name="outputFile">Output file to be created</param>
		/// <param name="inputFile">Input file containing CMS object</param>
		/// <param name="opts">Options</param>
		/// <returns>A positive number giving the size of the output file in bytes; 
		/// otherwise it returns an <see cref="General.ErrorLookup">error code</see> </returns>
		/// <remarks>
		/// The input file is expected to be a binary CMS object of type enveloped-data, 
		/// signed-data or compressed-data; otherwise it is an error.
		/// The type of input file is detected automatically. 
		/// By default the body is encoded in base64 encoding. 
		/// Use the <see cref="Options.EncodeBinary"/> option to encode the body in binary.
		/// </remarks>
		public static int Wrap(string outputFile, string inputFile, Smime.Options opts)
		{
			int r = SMIME_Wrap(outputFile, inputFile, "", (int)opts);
			return r;
		}

		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int SMIME_Extract(string szFileOut, string szFileIn, int nOptions);

		/// <summary>
		/// Extract the body from an S/MIME entity. 
		/// </summary>
		/// <param name="outputFile">Name of output file to be created</param>
		/// <param name="inputFile">Name of input file containing S/MIME entity</param>
		/// <param name="opts">Options</param>
		/// <returns>A positive number giving the size of the output file in bytes; 
		/// otherwise it returns an <see cref="General.ErrorLookup">error code</see> </returns>
		/// <remarks>This is designed to extract the body from an S/MIME entity with a content type of 
		/// <c>application/pkcs7-mime</c> with base64 or binary transfer encoding. 
		/// In practice, it will extract the body from almost any type of S/MIME (or MIME) file, 
		/// except one with quoted-printable transfer encoding.
		/// By default the output is encoded in binary.
		/// Use the <see cref="Options.EncodeBase64"/> option to encode the output in base64.
		/// </remarks>
		public static int Extract(string outputFile, string inputFile, Smime.Options opts)
		{
			int r = SMIME_Extract(outputFile, inputFile, (int)opts);
			return r;
		}

		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int SMIME_Query(StringBuilder szOutput, int nOutChars, string szFileIn, string szQuery, int nOptions);

		/// <summary>
		/// Query an S/MIME entity for selected information.
		/// </summary>
		/// <param name="inputFile">Name of file containing S/MIME entity</param>
		/// <param name="query">Query string (case insensitive)</param>
		/// <returns>String containing the result or an empty string if not found or error.</returns>
		/// <remarks>
		/// <para>Valid queries are:</para>
		/// <list type="table">
		/// <item>
		/// <term><c>"content-type"</c></term>
		/// <description>Value of Content-Type, e.g. <c>"application/pkcs7-mime"</c>.</description>
		/// </item>
		/// <item>
		/// <term><c>"smime-type"</c></term>
		/// <description>Value of smime-type parameter of Content-Type, e.g. , e.g. <c>"enveloped-data"</c>.</description>
		/// </item>
		/// <item>
		/// <term><c>"encoding"</c></term>
		/// <description>Value of Content-Transfer-Encoding, e.g. "base64".</description>
		/// </item>
		/// <item>
		/// <term><c>"name"</c></term>
		/// <description>Value of name parameter of Content-Type, e.g. "smime.p7m"</description>
		/// </item>
		/// <item>
		/// <term><c>"filename"</c></term>
		/// <description>Value of filename parameter of Content-Disposition, e.g. "smime.p7m".</description>
		/// </item>
		/// </list>
		///</remarks>
		public static string Query(string inputFile, string query)
		{
			int n = SMIME_Query(null, 0, inputFile, query, 0);
			if (n <= 0) return "";
			StringBuilder sb = new StringBuilder(n);
			SMIME_Query(sb, n, inputFile, query, 0);
			return sb.ToString();
		}
	}


	/// <summary>
	/// Signature creation and verification
	/// </summary>
	public class Sig
	{
		private Sig() {}	// Static methods only, so hide constructor.

		// PROTOTYPES FOR CORE DLL FUNCTIONS
		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int SIG_SignData(StringBuilder szOutput, int nOutChars, byte[] lpData, int nDataLen, string szKeyFile, string szPassword, string szAlgName, int nOptions);
		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int SIG_SignFile(StringBuilder szOutput, int nOutChars, string szDataFile, string szKeyFile, string szPassword, string szAlgName, int nOptions);
		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int SIG_VerifyData(string szSignature, byte[] lpData, int nDataLen, string szCertOrKeyFile, string szAlgName, int nOptions);
		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int SIG_VerifyFile(string szSignature, string szDataFile, string szCertOrKeyFile, string szAlgName, int nOptions);


		/* Internal constants */
		private const int PKI_SIG_USEDIGEST = 0x1000;
		private const int PKI_SIG_DETERMINISTIC = 0x2000;
		private const int PKI_SIG_ASN1DER = 0x200000;
		private const int PKI_ENCODE_HEX = 0x30000;
		private const int PKI_ENCODE_BASE64URL = 0x40000;


		/// <summary>
		/// Options for ECDSA signatures
		/// </summary>
		[Flags()]
		public enum SigOptions
		{
			/// <summary>
			/// Default options for ECDSA signature.
			/// </summary>
			Default = 0,
			/// <summary>
			/// Use the deterministic digital signature generation procedure of 
			/// [<a href="https://tools.ietf.org/html/rfc6979">RFC6979</a>] for ECDSA signature [default=random k]
			/// </summary>
			UseDeterministic = PKI_SIG_DETERMINISTIC,
			/// <summary>
			/// Form ECDSA signature value as a DER-encoded ASN.1 structure [default=<c>r||s</c>]
			/// </summary>
			Asn1DERStructure = PKI_SIG_ASN1DER,
		}

		/// <summary>
		/// Encodings for signature output
		/// </summary>
		public enum Encoding
		{
			/// <summary>
			///  Default encoding (base64)
			/// </summary>
			Default = 0, 
			/// <summary>
			/// Base64 encoding (default)
			/// </summary>
			Base64 = 0,
			/// <summary>
			/// URL-safe base64 encoding as in section 5 of [<a href="https://tools.ietf.org/html/rfc4648">RFC4648</a>]
			/// </summary>
			Base64url = PKI_ENCODE_BASE64URL,
			/// <summary>
			/// Base16 encoding (i.e. hexadecimal)
			/// </summary>
			Base16 = PKI_ENCODE_HEX,
		}

		/// <overloads>Compute a signature value over data in a byte array.</overloads>
		/// <summary>
		/// Compute a signature value over data in a byte array.
		/// </summary>
		/// <param name="data">input data to be signed</param>
		/// <param name="privateKeyFile">Name of private key file
		///  (or a string containing the key in PEM format, or an internal private key)</param>
		/// <param name="password">Password for the private key, if encrypted</param>
		/// <param name="sigAlg">Signature algorithm to be used</param>
		/// <returns>The signature encoded in base64, or an empty string on error</returns>
		/// <remarks>The output is a continuous string of base64 characters suitable for the
		/// <c>&lt;SignatureValue&gt;</c> of an XML-DSIG document.</remarks>
		public static string SignData(byte[] data, string privateKeyFile, string password, SigAlgorithm sigAlg)
		{
			int flags = (int)sigAlg;
			int n = SIG_SignData(null, 0, data, data.Length, privateKeyFile, password, "", flags);
			if (n <= 0) return "";
			StringBuilder sb = new StringBuilder(n);
			SIG_SignData(sb, n, data, data.Length, privateKeyFile, password, "", flags);
			return sb.ToString();
		}

		/// <summary>
		/// Compute a signature value over data in a byte array with extended options.
		/// </summary>
		/// <param name="data">input data to be signed</param>
		/// <param name="privateKeyFile">Name of private key file
		///  (or a string containing the key in PEM format, or an internal private key)</param>
		/// <param name="password">Password for the private key, if encrypted</param>
		/// <param name="sigAlg">Signature algorithm to be used</param>
		/// <param name="sigOpts">Options for ECDSA signatures</param>
		/// <param name="sigEncoding">Optional encodings for output</param>
		/// <returns>The encoded signature, or an empty string on error</returns>
		public static string SignData(byte[] data, string privateKeyFile, string password, SigAlgorithm sigAlg,
			SigOptions sigOpts, Sig.Encoding sigEncoding)
		{
			int flags = (int)sigAlg | (int)sigOpts | (int)sigEncoding;
			int n = SIG_SignData(null, 0, data, data.Length, privateKeyFile, password, "", flags);
			if (n <= 0) return "";
			StringBuilder sb = new StringBuilder(n);
			SIG_SignData(sb, n, data, data.Length, privateKeyFile, password, "", flags);
			return sb.ToString();
		}

		/// <summary>
		/// Compute a signature value over a message digest value.
		/// </summary>
		/// <param name="digest">digest value in a byte array</param>
		/// <param name="privateKeyFile">Name of private key file
		///  (or a string containing the key in PEM format, or an internal private key)</param>
		/// <param name="password">Password for the private key, if encrypted</param>
		/// <param name="sigAlg">Signature algorithm to be used</param>
		/// <returns>The signature encoded in base64, or an empty string on error</returns>
		/// <remarks>The output is a continuous string of base64 characters suitable for the
		/// <c>&lt;SignatureValue&gt;</c> of an XML-DSIG document.</remarks>
		/// <overloads>Compute a signature value over a message digest value.</overloads>
		public static string SignDigest(byte[] digest, string privateKeyFile, string password, SigAlgorithm sigAlg)
		{
			int flags = PKI_SIG_USEDIGEST | (int)sigAlg;
			int n = SIG_SignData(null, 0, digest, digest.Length, privateKeyFile, password, "", flags);
			if (n <= 0) return "";
			StringBuilder sb = new StringBuilder(n);
			SIG_SignData(sb, n, digest, digest.Length, privateKeyFile, password, "", flags);
			return sb.ToString();
		}

		/// <summary>
		/// Compute a signature value over a message digest value with extended options.
		/// </summary>
		/// <param name="digest">digest value in a byte array</param>
		/// <param name="privateKeyFile">Name of private key file
		///  (or a string containing the key in PEM format, or an internal private key)</param>
		/// <param name="password">Password for the private key, if encrypted</param>
		/// <param name="sigAlg">Signature algorithm to be used</param>
		/// <param name="sigOpts">Options for ECDSA signatures</param>
		/// <param name="sigEncoding">Optional encodings for output</param>
		/// <returns>The encoded signature, or an empty string on error</returns>
		public static string SignDigest(byte[] digest, string privateKeyFile, string password, SigAlgorithm sigAlg,
			SigOptions sigOpts, Sig.Encoding sigEncoding)
		{
			int flags = PKI_SIG_USEDIGEST | (int)sigAlg | (int)sigOpts | (int)sigEncoding;
			int n = SIG_SignData(null, 0, digest, digest.Length, privateKeyFile, password, "", flags);
			if (n <= 0) return "";
			StringBuilder sb = new StringBuilder(n);
			SIG_SignData(sb, n, digest, digest.Length, privateKeyFile, password, "", flags);
			return sb.ToString();
		}

		/// <summary>
		/// Compute a signature value over binary data in a file.
		/// </summary>
		/// <param name="dataFile">Name of input file containing data to be signed</param>
		/// <param name="privateKeyFile">Name of private key file
		///  (or a string containing the key in PEM format, or an internal private key)</param>
		/// <param name="password">Password for the private key, if encrypted</param>
		/// <param name="sigAlg">Signature algorithm to be used</param>
		/// <returns>The signature encoded in base64, or an empty string on error</returns>
		/// <remarks>The output is a continuous string of base64 characters suitable for the
		/// <c>&lt;SignatureValue&gt;</c> of an XML-DSIG document.</remarks>
		/// <overloads>Compute a signature value over binary data in a file.</overloads>
		public static string SignFile(string dataFile, string privateKeyFile, string password, SigAlgorithm sigAlg)
		{
			int flags = (int)sigAlg;
			int n = SIG_SignFile(null, 0, dataFile, privateKeyFile, password, "", flags);
			if (n <= 0) return "";
			StringBuilder sb = new StringBuilder(n);
			SIG_SignFile(sb, n, dataFile, privateKeyFile, password, "", flags);
			return sb.ToString();
		}

		/// <summary>
		/// Compute a signature value over binary data in a file with extended options.
		/// </summary>
		/// <param name="dataFile">Name of input file containing data to be signed</param>
		/// <param name="privateKeyFile">Name of private key file
		///  (or a string containing the key in PEM format, or an internal private key)</param>
		/// <param name="password">Password for the private key, if encrypted</param>
		/// <param name="sigAlg">Signature algorithm to be used</param>
		/// <param name="sigOpts">Options for ECDSA signatures</param>
		/// <param name="sigEncoding">Optional encodings for output</param>
		/// <returns>The encoded signature, or an empty string on error</returns>
		public static string SignFile(string dataFile, string privateKeyFile, string password, SigAlgorithm sigAlg,
			SigOptions sigOpts, Sig.Encoding sigEncoding)
		{
			int flags = (int)sigAlg | (int)sigOpts | (int)sigEncoding;
			int n = SIG_SignFile(null, 0, dataFile, privateKeyFile, password, "", flags);
			if (n <= 0) return "";
			StringBuilder sb = new StringBuilder(n);
			SIG_SignFile(sb, n, dataFile, privateKeyFile, password, "", flags);
			return sb.ToString();
		}

		/// <summary>
		/// Verify a signature value over data in a byte array
		/// </summary>
		/// <param name="sigStr">Containing the encoded signature value</param>
		/// <param name="data">Containing the input data to be verified</param>
		/// <param name="certOrKeyFile">Specifying the X.509 certificate or public key file name
		/// (or a string containing the certificate or key in PEM format or base64 representation, 
		/// or an internal key string). </param>
		/// <param name="sigAlg">Signature algorithm to be used</param>
		/// <returns>Zero (0) if the signature is valid; otherwise a negative <see cref="General.ErrorLookup">error code</see>.</returns>
		/// <remarks>A signature value is considered valid if it can be decrypted by the public key 
		/// in <c>szCertOrKeyFile</c> and the digest value of the data matches the original digest 
		/// of the data in the signature.
		/// Public keys in X.509 certificates are currently not supported for ECDSA signatures; only public key files or their string representations.
		/// Any valid encodings of the signature value are detected automatically.
		/// </remarks>
		public static int VerifyData(string sigStr, byte[] data, string certOrKeyFile, SigAlgorithm sigAlg)
		{
			int r = SIG_VerifyData(sigStr, data, data.Length, certOrKeyFile, "", (int)sigAlg);
			return r;
		}
		
		/// <summary>
		/// Verify a signature value over a message digest value of data
		/// </summary>
		/// <param name="sigStr">Containing the encoded signature value</param>
		/// <param name="digest">Byte array containing the message digest value of the data to be verified</param>
		/// <param name="certOrKeyFile">Specifying the X.509 certificate or public key file name
		/// (or a string containing the certificate or key in PEM format or base64 representation, 
		/// or an internal key string). </param>
		/// <param name="sigAlg">Signature algorithm to be used</param>
		/// <returns>Zero (0) if the signature is valid; otherwise a negative <see cref="General.ErrorLookup">error code</see>.</returns>
		/// <remarks>A signature value is considered valid if it can be decrypted by the public key 
		/// in <c>szCertOrKeyFile</c> and the digest value of the data matches the original digest 
		/// of the data in the signature.
		/// Public keys in X.509 certificates are currently not supported for ECDSA signatures; only public key files or their string representations.
		/// Any valid encodings of the signature value are detected automatically.
		/// </remarks>
		public static int VerifyDigest(string sigStr, byte[] digest, string certOrKeyFile, SigAlgorithm sigAlg)
		{
			int r = SIG_VerifyData(sigStr, digest, digest.Length, certOrKeyFile, "", (int)sigAlg + PKI_SIG_USEDIGEST);
			return r;
		}

		/// <summary>
		/// Verify a signature value over data in a file
		/// </summary>
		/// <param name="sigStr">Containing the encoded signature value</param>
		/// <param name="dataFile">Name of file containing data to be verified</param>
		/// <param name="certOrKeyFile">Specifying the X.509 certificate or public key file name
		/// (or a string containing the certificate or key in PEM format or base64 representation, 
		/// or an internal key string). </param>
		/// <param name="sigAlg">Signature algorithm to be used</param>
		/// <returns>Zero (0) if the signature is valid; otherwise a negative <see cref="General.ErrorLookup">error code</see>.</returns>
		/// <remarks>A signature value is considered valid if it can be decrypted by the public key 
		/// in <c>szCertOrKeyFile</c> and the digest value of the data matches the original digest 
		/// of the data in the signature.
		/// Public keys in X.509 certificates are currently not supported for ECDSA signatures; only public key files or their string representations.
		/// Any valid encodings of the signature value are detected automatically.
		/// </remarks>
		public static int VerifyFile(string sigStr, string dataFile, string certOrKeyFile, SigAlgorithm sigAlg)
		{
			int r = SIG_VerifyFile(sigStr, dataFile, certOrKeyFile, "", (int)sigAlg);
			return r;
		}

		/// <summary>
		/// Get the hash algorithm used in the signature algorithm
		/// </summary>
		/// <param name="sigAlg">Signature algorithm</param>
		/// <returns>Hash algorithm used in sigAlg</returns>
		public static HashAlgorithm GetHashAlgFromSigAlg(SigAlgorithm sigAlg)
		{
			switch (sigAlg)
			{         
				case SigAlgorithm.Rsa_Sha1:     return HashAlgorithm.Sha1;
				case SigAlgorithm.Rsa_Sha224:   return HashAlgorithm.Sha224;
				case SigAlgorithm.Rsa_Sha256:   return HashAlgorithm.Sha256;
				case SigAlgorithm.Rsa_Sha384:   return HashAlgorithm.Sha384;
				case SigAlgorithm.Rsa_Sha512:   return HashAlgorithm.Sha512;
				case SigAlgorithm.Rsa_Md5:      return HashAlgorithm.Md5;
				case SigAlgorithm.Ecdsa_Sha1:   return HashAlgorithm.Sha1;
				case SigAlgorithm.Ecdsa_Sha224: return HashAlgorithm.Sha224;
				case SigAlgorithm.Ecdsa_Sha256: return HashAlgorithm.Sha256;
				case SigAlgorithm.Ecdsa_Sha384: return HashAlgorithm.Sha384;
				case SigAlgorithm.Ecdsa_Sha512: return HashAlgorithm.Sha512;

				default: return HashAlgorithm.Sha1;
			}
		}

	}

	/// <summary>
	/// Elliptic curve cryptography
	/// </summary>
	public class Ecc
	{
		private Ecc()
		{ }	// Static methods only, so hide constructor.

		private const int PKI_KEY_FORMAT_PEM = 0x10000;
		private const int PKI_KEY_TYPE_PKCS8 = 0x40000;
		private const int PKI_PBE_PBES2 = 0x1000;
		private const int PKI_PBE_PBKDF2_DESEDE3 = 0x1010;
		private const int PKI_PBE_PBKDF2_AES128 = 0x1020;
		private const int PKI_PBE_PBKDF2_AES192 = 0x1030;
		private const int PKI_PBE_PBKDF2_AES256 = 0x1040;
		/*
		private const int PKI_PBE_SCRYPT_AES128  = 0x1820;
		private const int PKI_PBE_SCRYPT_AES256  = 0x1840;
		*/

		/// <summary>
		/// Supported curve names
		/// </summary>
		public enum CurveName
		{
			/// <summary>
			/// NIST curve P-192
			/// </summary>
			Secp192r1,
			/// <summary>
			/// NIST curve P-224
			/// </summary>
			Secp224r1,
			/// <summary>
			/// NIST curve P-256
			/// </summary>
			Secp256r1,
			/// <summary>
			/// NIST curve P-384
			/// </summary>
			Secp384r1,
			/// <summary>
			/// NIST curve P-521
			/// </summary>
			Secp521r1,
			/// <summary>
			/// "Bitcoin" curve
			/// </summary>
			Secp256k1,
			/// <summary>
			/// NIST curve P-192 (synonym for <c>secp192r1</c>)
			/// </summary>
			P_192,
			/// <summary>
			/// NIST curve P-256 (synonym for <c>secp256r1</c>)
			/// </summary>
			P_224,
			/// <summary>
			/// NIST curve P-224 (synonym for <c>secp224r1</c>)
			/// </summary>
			P_256,
			/// <summary>
			/// NIST curve P-384 (synonym for <c>secp384r1</c>)
			/// </summary>
			P_384,
			/// <summary>
			/// NIST curve P-521 (synonym for <c>secp521r1</c>)
			/// </summary>
			P_521,
			/// <summary>
			/// Alternative name for NIST curve P-192
			/// </summary>
			Prime192v1,
			/// <summary>
			/// Alternative name for NIST curve P-256
			/// </summary>
			Prime256v1,
		};

		/// <summary>
		/// Format for output files
		/// </summary>
		public enum Format
		{
			/// <summary>
			/// Default = binary
			/// </summary>
			Default = 0,
			/// <summary>
			/// Binary DER-encoded
			/// </summary>
			Binary = 0,
			/// <summary>
			/// PEM-encoded text file
			/// </summary>
			PEM = PKI_KEY_FORMAT_PEM,
		};

		/// <summary>
		/// Password-based encryption scheme to encrypt the private key file
		/// </summary>
		public enum PbeScheme
		{
			/// <summary>
			/// Default option (pbeWithSHAAnd3-KeyTripleDES-CBC)
			/// </summary>
			Default = 0,
			/// <summary>
			/// pbeWithSHAAnd3-KeyTripleDES-CBC from PKCS#12
			/// </summary>
			PbeWithSHAAnd_KeyTripleDES_CBC = 0,
			/// <summary>
			/// "pkcs5PBES2" with key derivation function "pkcs5PBKDF2" and encryption scheme "des-EDE3-CBC"
			/// </summary>
			Pbe_Pbkdf2_des_EDE3_CBC = PKI_PBE_PBKDF2_DESEDE3,
			/// <summary>
			/// "pkcs5PBES2" with key derivation function "pkcs5PBKDF2" and encryption scheme "aes128-CBC"
			/// </summary>
			Pbe_Pbkdf2_aes128_CBC = PKI_PBE_PBKDF2_AES128,
			/// <summary>
			/// "pkcs5PBES2" with key derivation function "pkcs5PBKDF2" and encryption scheme "aes192-CBC"
			/// </summary>
			Pbe_Pbkdf2_aes192_CBC = PKI_PBE_PBKDF2_AES192,
			/// <summary>
			/// "pkcs5PBES2" with key derivation function "pkcs5PBKDF2" and encryption scheme "aes256-CBC"
			/// </summary>
			Pbe_Pbkdf2_aes256_CBC = PKI_PBE_PBKDF2_AES256,
		}

		/// <summary>
		/// Key type for unencrypted key file
		/// </summary>
		public enum KeyType
		{
			/// <summary>
			/// Default type: <c>SubjectPublicKeyInfo</c> for an EC public key
			/// or <c>ECPrivateKey</c> for an EC private key
			/// </summary>
			Default = 0,
			/// <summary>
			/// Save private key in PKCS#8 <c>PrivateKeyInfo</c> format (ignored for a public key)
			/// </summary>
			Pkcs8PrivateKeyInfo = PKI_KEY_TYPE_PKCS8,
		}

 
		// PROTOTYPES
		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int ECC_ReadKeyByCurve(StringBuilder szOutput, int nOutChars, string szHexKey, string szCurveName, int nOptions);
		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int ECC_PublicKeyFromPrivate(StringBuilder szOutput, int nOutChars, string szIntKeyString, int nOptions);

		/// <summary>
		/// Read an EC key from its hexadecimal representation.
		/// </summary>
		/// <param name="hexKey">hexadecimal representation of the key, private or public</param>
		/// <param name="curveName">name of the elliptic curve</param>
		/// <returns>The key in ephemeral "internal" representation, or the empty string on error</returns>
		/// <remarks>An EC private key <c>w</c> is represented as <c>HEX(w)</c>
		/// and a public key <c>(x,y)</c> in the uncompressed X9.63 form <c>04||HEX(x)||HEX(y)</c>.</remarks>
		public static string ReadKeyByCurve(string hexKey, Ecc.CurveName curveName)
		{
			int nChars = ECC_ReadKeyByCurve(null, 0, hexKey, curveName.ToString(), 0);
			if (nChars <= 0) return String.Empty;
			StringBuilder sb = new StringBuilder(nChars);
			nChars = ECC_ReadKeyByCurve(sb, nChars, hexKey, curveName.ToString(), 0);
			return sb.ToString(0, nChars);
		}
		/// <summary>
		/// Convert an internal EC private key string into an internal EC public key string.
		/// </summary>
		/// <param name="internalKey">the private key as an internal key string</param>
		/// <returns>The public key in ephemeral "internal" representation, or the empty string on error</returns>
		public static string PublicKeyFromPrivate(string internalKey)
		{
			int nChars = ECC_PublicKeyFromPrivate(null, 0, internalKey, 0);
			if (nChars <= 0) return String.Empty;
			StringBuilder sb = new StringBuilder(nChars);
			nChars = ECC_PublicKeyFromPrivate(sb, nChars, internalKey, 0);
			return sb.ToString(0, nChars);
		}

		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int ECC_MakeKeys(string szPubKeyFile, string szPriKeyFile, string szCurveName, string szPassword, string szParams, int nOptions);

		/// <overloads>Generate an EC public/private key pair.</overloads>
		/// <summary>
		/// Generate an EC public/private key pair and save as two key files.
		/// </summary>
		/// <param name="publicKeyfile">name of public key file to be created.</param>
		/// <param name="privateKeyFile">name of encrypted private key file to be created.</param>
		/// <param name="curveName">name of elliptic curve.</param>
		/// <param name="password">password to be used for the encrypted key file.</param>
		/// <returns>Zero if successful or non-zero <see cref="General.ErrorLookup">error code</see></returns>
		/// <remarks>Saves key files with all default settings.</remarks>
		public static int MakeKeys(string publicKeyfile, string privateKeyFile, CurveName curveName, string password)
		{
			int r = ECC_MakeKeys(publicKeyfile, privateKeyFile, curveName.ToString(), password, "", 0);
			return r;
		}

		/// <summary>
		/// Generate an EC public/private key pair with extended options.
		/// </summary>
		/// <param name="publicKeyfile">name of public key file to be created</param>
		/// <param name="privateKeyFile">name of encrypted private key file to be created</param>
		/// <param name="curveName">name of elliptic curve</param>
		/// <param name="password">password to be used for the encrypted key file.</param>
		/// <param name="pbes">Password-based encryption scheme to encrypt private key 
		/// [default = <c>pbeWithSHAAnd3-KeyTripleDES-CBC</c>]</param>
		/// <param name="paramString">Optional parameters. 
		/// A set of attribute name=value pairs separated by a semicolon ";" (see remarks).
		/// Set as <c>""</c> for defaults.
		/// </param>
		/// <param name="fileFormat">Format to save file [default = DER binary]</param>
		/// <returns>Zero if successful or non-zero <see cref="General.ErrorLookup">error code</see></returns>
		/// <remarks>
		/// <para>Valid name-value pairs for <c>paramString</c> are:</para>
		/// <list type="table">
		/// <item>
		/// <term><b>count</b>=integer</term>
		/// <term>To set the iteration count used in the PBKDF2 method, 
		/// e.g. <c>"count=5000;"</c> [default=2048].
		/// </term>
		/// </item>
		/// <item><term><b>prf</b>=hmac-name</term>
		/// <term>To change the HMAC algorithm used in the PBKDF2 method,
		/// e.g. <c>"prf=hmacwithSHA256;"</c> [default=<c>hmacwithSHA1</c>].
		/// </term></item>
		/// <item><term><b>rngseed</b>=string</term>
		/// <term>To add some user-supplied entropy for the key generation process,
		/// e.g. <c>"rngseed=pqrrr1234xyz;"</c>.
		/// </term></item>
		/// </list>
		/// </remarks>
		/// <example><code>
		/// n = Ecc.MakeKeys(pubkeyfile, prikeyfile, Ecc.CurveName.Prime192v1, "password", 
		///        Ecc.PbeScheme.Pbe_Pbkdf2_aes128_CBC, "count=3999;prf=hmacWithSha256", Ecc.Format.PEM);
		/// </code></example>
		public static int MakeKeys(string publicKeyfile, string privateKeyFile, CurveName curveName,
			string password, PbeScheme pbes, string paramString, Format fileFormat)
		{
			int flags = (int)pbes | (int)fileFormat;
			int r = ECC_MakeKeys(publicKeyfile, privateKeyFile, curveName.ToString(), password, paramString, flags);
			return r;
		}

		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int ECC_SaveEncKey(string szFileOut, string szIntKeyString, string szPassword, string szParams, int nOptions);

		/// <summary>
		/// Save an internal EC private key string to an encrypted private key file.
		/// </summary>
		/// <param name="outputFile">name of key file to be created</param>
		/// <param name="internalKey">the private key in an internal key string</param>
		/// <param name="password">the password to be used for the encrypted key file</param>
		/// <param name="pbes">Password-based encryption scheme to encrypt private key 
		/// [default = <c>pbeWithSHAAnd3-KeyTripleDES-CBC</c>]</param>
		/// <param name="paramString">Optional parameters. 
		/// A set of attribute name=value pairs separated by a semicolon ";" (see remarks).
		/// Set as <c>""</c> for defaults.
		/// </param> 
		/// <param name="fileFormat">Format to save file [default = DER binary]</param>
		/// <returns>Zero if successful or non-zero <see cref="General.ErrorLookup">error code</see></returns>
		/// <remarks>
		/// <para>Valid name-value pairs for <c>paramString</c> are:</para>
		/// <list type="table">
		/// <item>
		/// <term><b>count</b>=integer</term>
		/// <term>To set the iteration count used in the PBKDF2 method, 
		/// e.g. <c>"count=5000;"</c> [default=2048].
		/// </term>
		/// </item>
		/// <item><term><b>prf</b>=hmac-name</term>
		/// <term>To change the HMAC algorithm used in the PBKDF2 method,
		/// e.g. <c>"prf=hmacwithSHA256;"</c> [default=<c>hmacwithSHA1</c>].
		/// </term></item>
		/// </list>
		/// </remarks>
		public static int SaveEncKey(string outputFile, string internalKey,
			string password, PbeScheme pbes, string paramString, Format fileFormat)
		{
			int flags = (int)pbes | (int)fileFormat;
			int r = ECC_SaveEncKey(outputFile, internalKey, password, paramString, flags);
			return r;
		}

		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int ECC_SaveKey(string szFileOut, string szIntKeyString, int nOptions);

		/// <summary>
		/// Save an internal EC key string (public or private) to an unencrypted key file.
		/// </summary>
		/// <param name="outputFile">Name of key file to be created</param>
		/// <param name="internalKey">the private or public EC key in an internal key string</param>
		/// <param name="keyType">Key structure for private key (ignored for public)</param>
		/// <param name="fileFormat">Format to save file [default = DER binary]</param>
		/// <returns>If successful, the return value is zero; otherwise it returns a nonzero <see cref="General.ErrorLookup">error code</see></returns>
		public static int SaveKey(string outputFile, string internalKey, KeyType keyType, Format fileFormat)
		{
			int flags = (int)keyType | (int)fileFormat;
			int r = ECC_SaveKey(outputFile, internalKey, flags);
			return r;
		}

		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int ECC_ReadPrivateKey(StringBuilder szOutput, int nOutChars, string szKeyFileOrString, string szPassword, int nOptions);

		/// <summary>
		/// Read from a file or string containing an EC private key into an "internal" private key string.
		/// </summary>
		/// <param name="keyFileOrString">Name of private key file or a PEM String containing the key</param>
		/// <param name="password">Password for private key, if encrypted; or <c>""</c> if not</param>
		/// <returns>StringBuilder containing an internal representation of the
		/// private key; or an empty StringBuilder if error </returns>
		/// <remarks>This returns a StringBuilder, not a string, to allow secure wiping. 
		/// Use sb.ToString() to obtain a string. Use <see cref="Wipe.String">Wipe.String(sb)</see> to clear.
		/// </remarks>
		public static StringBuilder ReadPrivateKey(string keyFileOrString, string password)
		{
			StringBuilder sb = new StringBuilder(0);
			int n = ECC_ReadPrivateKey(sb, 0, keyFileOrString, password, 0);
			if (n <= 0) return sb;
			sb = new StringBuilder(n);
			ECC_ReadPrivateKey(sb, sb.Capacity, keyFileOrString, password, 0);
			return sb;
		}

		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int ECC_ReadPublicKey(StringBuilder szOutput, int nOutChars, string szKeyFileOrString, int nOptions);

		/// <summary>
		/// Read from a file or string containing an EC public key into an "internal" private key string.
		/// </summary>
		/// <param name="keyFileOrString">Name of public key file or a PEM String containing the key</param>
		/// <returns>StringBuilder containing an internal representation of the
		/// public key; or an empty StringBuilder if error </returns>
		/// <remarks>This returns a StringBuilder, not a string. 
		/// Use sb.ToString() to obtain a string.
		/// </remarks>
		public static StringBuilder ReadPublicKey(string keyFileOrString)
		{
			StringBuilder sb = new StringBuilder(0);
			int n = ECC_ReadPublicKey(sb, 0, keyFileOrString, 0);
			if (n <= 0) return sb;
			sb = new StringBuilder(n);
			ECC_ReadPublicKey(sb, sb.Capacity, keyFileOrString, 0);
			return sb;
		}

		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int ECC_QueryKey(StringBuilder szOutput, int nOutChars, string szIntKeyString, string szQuery, int nOptions);

		/// <summary>
		/// Query an EC key string for selected information.
		/// </summary>
		/// <param name="internalKey">containing the key as an internal key string</param>
		/// <param name="query">Query string (case insensitive)</param>
		/// <returns>String containing the result or an empty string if not found or error.</returns>
		/// <remarks>
		/// <para>Valid queries are:</para>
		/// <list type="table">
		/// <item>
		/// <term><c>"curveName"</c></term>
		/// <description>Name of the curve.</description>
		/// </item>
		/// <item>
		/// <term><c>"keyBits"</c></term>
		/// <description>Number of bits in the key.</description>
		/// </item>
		/// <item>
		/// <term><c>"isPrivate"</c></term>
		/// <description>"1" if key is a private key; "0" if not.</description>
		/// </item>
		/// <item>
		/// <term><c>"privateKey"</c></term>
		/// <description>Value of the private key in hex format. </description>
		/// </item>
		/// <item>
		/// <term><c>"publicKey"</c></term>
		/// <description>Value of the public key in hex format.</description>
		/// </item>
		/// </list>
		///</remarks>
		public static string QueryKey(string internalKey, string query)
		{
			int n;
			StringBuilder sb = new StringBuilder(0);

			// ECC_QueryKey either returns an integer result directly or sets the string
			n = ECC_QueryKey(null, 0, internalKey, query, (int)myQuery.PKI_QUERY_GETTYPE);
			if (n == (int)myQuery.PKI_QUERY_STRING)
			{
				n = ECC_QueryKey(sb, 0, internalKey, query, 0);
				if (n <= 0) return String.Empty;
				sb = new StringBuilder(n);
				ECC_QueryKey(sb, sb.Capacity, internalKey, query, 0);
			} else
			{
				n = ECC_QueryKey(sb, 0, internalKey, query, 0);
			}
			if (sb.Length == 0)
			{	// Result is an integer returned in n, so set our return value as a string
				sb.Append(n);
			}
			return sb.ToString();
		}

		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int ECC_KeyHashCode(string szIntKeyString);
		/// <summary>
		///  Compute the hash code of an "internal" ECC public or private key string
		/// </summary>
		/// <param name="intKeyString">Internal key string</param>
		/// <returns>A 32-bit hash code for the key, or zero on error.</returns>
		/// <remarks>Should be the same for a matching private and public key.</remarks>
		public static int KeyHashCode(string intKeyString)
		{
			return ECC_KeyHashCode(intKeyString);
		}
	
	}

	/// <summary>
	/// Character conversion routines
	/// </summary>
	public class Cnv
	{
		private Cnv()
		{}	// Static methods only, so hide constructor.

		/// <summary>
		/// Conversion directions for ByteEncoding
		/// </summary>
		public enum EncodingConversion
		{
			/// <summary>
			/// Converts UTF-8-encoded bytes into Latin-1-encoded
			/// </summary>
			Utf8_From_Latin1 = 1,
			/// <summary>
			/// Converts Latin-1-encoded bytes into UTF-8-encoded
			/// </summary>
			Latin1_From_Utf8 = 2,
		}

		/// <summary>
		/// Byte order 
		/// </summary>
		public enum EndianNess
		{
			/// <summary>
			/// Most-significant byte first
			/// </summary>
			BigEndian = 0,
			/// <summary>
			/// Least-significant byte first
			/// </summary>
			LittleEndian = 1,
		}

		// HEX CONVERSION PROTOTYPES
		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int CNV_HexStrFromBytes(StringBuilder sboutput, int out_len, byte[] input, int in_len);
		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int CNV_BytesFromHexStr(byte[] output, int out_len, string input);
		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int CNV_HexFilter(StringBuilder sboutput, string input, int len);

		/// <summary>
		/// Convert 8-bit binary data to equivalent hexadecimal string format.
		/// </summary>
		/// <param name="binaryData">binary data in byte array</param>
		/// <returns>Hex-encoded string.</returns>
		public static string ToHex(byte[] binaryData)
		{
			int nBytes = binaryData.Length;
			int nChars = 2 * nBytes;
			if (nBytes == 0) return String.Empty;
			StringBuilder sb = new StringBuilder(nChars);
			nChars = CNV_HexStrFromBytes(sb, nChars, binaryData, nBytes);
			return sb.ToString(0, nChars);
		}

		/// <summary>
		/// Convert the specified string representation of a value consisting of hexadecimal (base 16) digits to an equivalent array of 8-bit unsigned integers.
		/// </summary>
		/// <param name="s">Hex-encoded string</param>
		/// <returns>Binary data in byte array, or an empty array on error.</returns>
		/// <remarks>Whitespace and ASCII punctuation characters are ignored,
		/// but other non-hex characters will cause an error.</remarks>
		public static byte[] FromHex(string s)
		{
			// [v11.1] changed to cope with invalid hex chars
			int n = CNV_BytesFromHexStr(null, 0, s);
			if (n <= 0) return new byte[0];
			byte[] b = new byte[n];
			n = CNV_BytesFromHexStr(b, n, s);
			if (n <= 0) return new byte[0];
			return b;
		}

		/// <summary>
		/// Convert a hexadecimal-encoded string into a text string.
		/// </summary>
		/// <param name="s">Hex-encoded data</param>
		/// <returns>String value</returns>
		/// <remarks>Uses the 'Default' encoding for the system's current ANSI code page,
		/// usually code page 1252 (similar to Latin-1).
		/// This assumes the user knows the resulting characters are all printable.
		/// </remarks>
		public static string StringFromHex(string s)
		{
			byte[] b = FromHex(s);
			if (b.Length == 0) return String.Empty;
			return System.Text.Encoding.Default.GetString(b);
		}

		/// <summary>
		/// Filter non-hexadecimal characters from a string.
		/// </summary>
		/// <param name="s">Input string to be filtered</param>
		/// <returns>Filtered string</returns>
		public static string HexFilter(string s)
		{
			int nChars;
			if (s == null) return String.Empty;
			StringBuilder sb = new StringBuilder(s.Length);
			nChars = CNV_HexFilter(sb, s, s.Length);
			if (nChars <= 0) return String.Empty;
			return sb.ToString(0, nChars);
		}

		/* BASE64 CONVERSION FUNCTIONS */
		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int CNV_B64StrFromBytes(StringBuilder sbOutput, int nOutChars, byte[] input, int nbytes);
		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int CNV_BytesFromB64Str(byte[] output, int out_len, string input);
		[DllImport("diCrPKI.dll",CharSet=CharSet.Ansi)]
		static extern int CNV_B64Filter(StringBuilder sbOutput, string input, int len);

		/// <overloads>Two overloads: one for bytes, one for a string</overloads>
		/// <summary>
		/// Convert 8-bit binary data to equivalent base64-encoded string format
		/// </summary>
		/// <param name="binaryData">binary data</param>
		/// <returns>Base64-encoded string</returns>
		public static string ToBase64(byte[] binaryData)
		{
			int nChars = CNV_B64StrFromBytes(null, 0, binaryData, binaryData.Length);
			if (nChars <= 0) return String.Empty;
			StringBuilder sb = new StringBuilder(nChars);
			nChars = CNV_B64StrFromBytes(sb, nChars, binaryData, binaryData.Length);
			if (nChars <= 0) return String.Empty;
			return sb.ToString(0, nChars);
		}

		/// <summary>
		/// Convert a string of ANSI characters to equivalent base64-encoded string format.
		/// </summary>
		/// <param name="s">String of data to be encoded</param>
		/// <returns>Base64-encoded data</returns>
		/// <remarks>Uses the 'Default' encoding for the system's current ANSI code page</remarks>
		public static string ToBase64(string s)
		{
			byte[] b = System.Text.Encoding.Default.GetBytes(s);
			return ToBase64(b);
		}

		/// <summary>
		/// Convert a base64-encoded string to an equivalent array of 8-bit unsigned integers.
		/// </summary>
		/// <param name="s">Base64-encoded data</param>
		/// <returns>Binary data in byte array, or an empty array on error.</returns>
		/// <remarks>Whitespace characters are ignored,
		/// but other non-base64 characters will cause an error.</remarks>
		public static byte[] FromBase64(string s)
		{
			int n = CNV_BytesFromB64Str(null, 0, s);
			if (n <= 0) return new byte[0];
			byte[] b = new byte[n];
			n = CNV_BytesFromB64Str(b, n, s);
			if (n <= 0) return new byte[0];
			return b;
		}

		/// <summary>
		/// Convert a base64-encoded string into a text string.
		/// </summary>
		/// <param name="s">Base64-encoded data</param>
		/// <returns>String value</returns>
		/// <remarks>Uses the 'Default' encoding for the system's current ANSI code page. 
		/// This assumes the user knows the resulting characters are all printable.</remarks>
		public static string StringFromBase64(string s)
		{
			byte[] b = FromBase64(s);
			if (b.Length == 0) return String.Empty;
			return System.Text.Encoding.Default.GetString(b);
		}

		/// <summary>
		/// Filter non-base64 characters from a string.
		/// </summary>
		/// <param name="s">String to be filtered</param>
		/// <returns>Filtered string</returns>
		/// <remarks>Valid base64 characters are [0-9A-Za-z+/=]</remarks>
		public static string Base64Filter(string s)
		{
			int nChars;
			StringBuilder sb = new StringBuilder(s.Length);
			nChars = CNV_B64Filter(sb, s, s.Length);
			if (nChars <= 0) return String.Empty;
			return sb.ToString(0, nChars);
		}

		// EXTRA CONVERSIONS DIRECTLY BETWEEN HEX AND BASE64
		/// <summary>
		/// Convert base64-encoded data into hexadecimal-encoded data.
		/// </summary>
		/// <param name="s">Base64-encoded data</param>
		/// <returns>Hex-encoded data</returns>
		public static string HexFromBase64(string s)
		{
			byte[] b = FromBase64(s);
			if (b.Length == 0) return String.Empty;
			return ToHex(b);
		}
		/// <summary>
		/// Convert hexadecimal-encoded data into base64-encoded data.
		/// </summary>
		/// <param name="s">Hex-encoded data</param>
		/// <returns>Base64-encoded data</returns>
		public static string Base64FromHex(string s)
		{
			byte[] b = FromHex(s);
			if (b.Length == 0) return String.Empty;
			return ToBase64(b);
		}

		/* BASE58 CONVERSION FUNCTIONS */
		// Added [v11.0]
		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int CNV_Base58FromBytes(StringBuilder sbOutput, int nOutChars, byte[] input, int nbytes);
		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int CNV_Base58ToBytes(byte[] output, int out_len, string input);
 
		/// <summary>
		/// Convert 8-bit binary data to equivalent base58-encoded string format.
		/// </summary>
		/// <param name="binaryData">binary data</param>
		/// <returns>Base58-encoded string</returns>
		/// <remarks>This uses the "Bitcoin" scheme of base58 encoding 
		/// where the leading character '1' is reserved for representing 
		/// an entire leading zero byte.
		/// </remarks>
		public static string ToBase58(byte[] binaryData)
		{
			int nChars = CNV_Base58FromBytes(null, 0, binaryData, binaryData.Length);
			if (nChars <= 0) return String.Empty;
			StringBuilder sb = new StringBuilder(nChars);
			nChars = CNV_Base58FromBytes(sb, nChars, binaryData, binaryData.Length);
			if (nChars <= 0) return String.Empty;
			return sb.ToString(0, nChars);
		}

		/// <summary>
		/// Convert a base58-encoded string to an equivalent array of 8-bit unsigned integers.
		/// </summary>
		/// <param name="s">Base58-encoded data</param>
		/// <returns>Data as array of bytes</returns>
		/// <remarks>This uses the "Bitcoin" scheme of base58 encoding 
		/// where the leading character '1' is reserved for representing 
		/// an entire leading zero byte.
		/// </remarks>
		public static byte[] FromBase58(string s)
		{
			int n = CNV_Base58ToBytes(null, 0, s);
			if (n <= 0) return new byte[0];
			byte[] b = new byte[n];
			n = CNV_Base58ToBytes(b, n, s);
			if (n <= 0) return new byte[0];
			return b;
		}


		/* UTF-8 FUNCTIONS */
		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int CNV_CheckUTF8Bytes(byte[] b, int nbytes);
		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int CNV_CheckUTF8File(string fileName);

		/// <summary>
		/// Check that a byte array contains only valid UTF-8 encoded characters.
		/// </summary>
		/// <param name="b">input byte array to check</param>
		/// <returns>
		/// <para>Zero if the encoded bytes is invalid UTF-8, 
		/// or a positive number if the input contains valid UTF-8 data, where the value of the
		/// number indicates the nature of the encoded characters:
		/// </para>
		/// <list type="table">
		/// <item><term>0</term><description>Not valid UTF-8</description></item>
		/// <item><term>1</term><description>Valid UTF-8, all chars are 7-bit ASCII</description></item>
		/// <item><term>2</term><description>Valid UTF-8, contains at least one multi-byte character equivalent to 8-bit ANSI</description></item>
		/// <item><term>3</term><description>Valid UTF-8, contains at least one multi-byte character
		/// that cannot be represented in a single-byte character set</description></item>
		///</list>
		/// </returns>
		/// <remarks>
		/// 'Overlong' UTF-8 sequences and illegal surrogates are rejected as invalid.
		///</remarks>
		public static int CheckUTF8(byte[] b)
		{
			return CNV_CheckUTF8Bytes(b, b.Length);
		}

		//DELETED IN [v11.0]
		//public static int CheckUTF8(string s)


		/// <summary>
		/// Check that a file contains only valid UTF-8 encoded characters
		/// </summary>
		/// <param name="fileName">name of file to check</param>
		/// <returns>
		/// <para>Zero if the encoded bytes is invalid UTF-8, 
		/// or a positive number if the input contains valid UTF-8 data, where the value of the
		/// number indicates the nature of the encoded characters:
		/// </para>
		/// <list type="table">
		/// <item><term>0</term><description>Not valid UTF-8</description></item>
		/// <item><term>1</term><description>Valid UTF-8, all chars are 7-bit ASCII</description></item>
		/// <item><term>2</term><description>Valid UTF-8, contains at least one multi-byte character equivalent to 8-bit ANSI</description></item>
		/// <item><term>3</term><description>Valid UTF-8, contains at least one multi-byte character
		/// that cannot be represented in a single-byte character set</description></item>
		///</list>
		/// </returns>
		/// <remarks>
		/// 'Overlong' UTF-8 sequences and illegal surrogates are rejected as invalid.
		///</remarks>
		public static int CheckUTF8File(string fileName)
		{
			return CNV_CheckUTF8File(fileName);
		}
		
		// UTF-8/LATIN-1 BYTE ENCODING CONVERSIONS
		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int CNV_ByteEncoding(byte[] output, int nbout, byte[] input, int nbin, int options);

		/// <summary>
		/// Convert encoding of byte array between UTF-8 and Latin-1
		/// </summary>
		/// <param name="data">Input data to be converted</param>
		/// <param name="direction">Direction of conversion</param>
		/// <returns>Converted data (or empty array on error)</returns>
		/// <remarks>
		/// Converting UTF-8 from Latin-1 assumes the input is from the 8-bit Latin-1 character set 
		/// and so will <em>always</em> produce output that is valid UTF-8.
		/// However, for Latin-1 from UTF-8, the input <em>must</em> contain a
		/// valid sequence of UTF-8-encoded bytes and this must be convertible
		/// to a single-byte character set, or an error will be returned.
		/// </remarks>
		public static byte[] ByteEncoding(byte[] data, EncodingConversion direction)
		{
			int option = (int)direction;
			byte[] b;
			int len = CNV_ByteEncoding(null, 0, data, data.Length, option);
			if (len <= 0) return new byte[0];
			b = new byte[len];
			len = CNV_ByteEncoding(b, b.Length, data, data.Length, option);
			if (len <= 0)
				b = new byte[0];
			return b;
		}

		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int CNV_ReverseBytes(byte[] lpOutput, byte[] lpInput, int nBytes);
		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int CNV_NumToBytes(byte[] lpOutput, int nOutBytes, int nNumber, int nOptions);
		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int CNV_NumFromBytes(byte[] lpInput, int nBytes, int nOptions);

		/// <summary>
		/// Reverse the order of a byte array
		/// </summary>
		/// <param name="data">Input data to be reversed</param>
		/// <returns>Byte array in reverse order</returns>
		public static byte[] ReverseBytes(byte[] data)
		{
			byte[] b;
			int r;
			b = new byte[data.Length];
			r = CNV_ReverseBytes(b, data, b.Length);
			return b;
		}

		/// <summary>
		/// Convert a 32-bit integer to an array of 4 bytes. 
		/// </summary>
		/// <param name="n">Integer to be converted</param>
		/// <param name="endn">Byte order</param>
		/// <returns>Byte array containing representation of integer in given order</returns>
		/// <example><code>
		/// byte[] bb = Cnv.NumToBytes(0xdeadbeef, Cnv.EndianNess.BigEndian);
		/// Console.WriteLine(Cnv.ToHex(bb));  // DEADBEEF
		/// byte[] bl = Cnv.NumToBytes(0xdeadbeef, Cnv.EndianNess.LittleEndian);
		/// Console.WriteLine(Cnv.ToHex(bl));  // EFBEADDE
		/// </code></example>
		public static byte[] NumToBytes(uint n, EndianNess endn)
		{
			int flags = (int)endn;
			int r;
			byte[] b = new byte[4];
			r = CNV_NumToBytes(b, b.Length, (int)n, flags);
			return b;
		}

		/// <summary>
		/// Convert the leftmost four bytes of an array to an unsigned 32-bit integer.
		/// </summary>
		/// <param name="b">Byte array to be converted</param>
		/// <param name="endn">Byte order</param>
		/// <returns>Integer value</returns>
		/// <remarks>An array shorter than 4 bytes will be padded on the right with zeros</remarks>
		/// <example><code>
		/// byte[] b = new byte[4] { 0xde, 0xad, 0xbe, 0xef };
		/// uint nb = Cnv.NumFromBytes(b, Cnv.EndianNess.BigEndian);
		/// Console.WriteLine("0x" + nb.ToString("x8"));  // 0xdeadbeef
		/// uint nl = Cnv.NumFromBytes(b, Cnv.EndianNess.LittleEndian);
		/// Console.WriteLine("0x" + nl.ToString("x8"));  // 0xefbeadde
		/// </code></example>
		public static uint NumFromBytes(byte[] b, EndianNess endn)
		{
			int flags = (int)endn;
			uint n = (uint)CNV_NumFromBytes(b, b.Length, flags);
			return n;
		}


	}
	// COMMON INTERNAL FUNCTIONS
	internal class MyInternals
	{
		// A common internal function to return the required string for the mode
		public static string ModeString(Mode mode)
		{
			switch(mode)
			{
				case Mode.CBC:
					return "CBC";
				case Mode.CFB:
					return "CFB";
				case Mode.OFB:
					return "OFB";
				case Mode.CTR:
					return "CTR";
				case Mode.ECB:
				default:
					return "ECB";
			}
		}
		// A common internal function to return the length of the message digest
		public static int HashBytes(HashAlgorithm alg)
		{
			switch(alg)
			{
				case HashAlgorithm.Sha1:
					return (int)HashLen.PKI_SHA1_BYTES;
				case HashAlgorithm.Sha224:
					return (int)HashLen.PKI_SHA224_BYTES;
				case HashAlgorithm.Sha256:
					return (int)HashLen.PKI_SHA256_BYTES;
				case HashAlgorithm.Sha384:
					return (int)HashLen.PKI_SHA384_BYTES;
				case HashAlgorithm.Sha512:
					return (int)HashLen.PKI_SHA512_BYTES;
				case HashAlgorithm.Md2:
					return (int)HashLen.PKI_MD2_BYTES;
				case HashAlgorithm.Md5:
					return (int)HashLen.PKI_MD5_BYTES;
				case HashAlgorithm.Ripemd160:
					return (int)HashLen.PKI_RMD160_BYTES;
				case HashAlgorithm.Bitcoin160:
					return (int)HashLen.PKI_BTC160_BYTES;
				default:
					return (int)HashLen.PKI_MAX_HASH_BYTES;
			}
		}
		public static int BlockSize(CipherAlgorithm alg)
		{
			switch (alg)
			{
				case CipherAlgorithm.Aes128:
				case CipherAlgorithm.Aes192:
				case CipherAlgorithm.Aes256:
					return 16;
				case CipherAlgorithm.Tdea:
				default:
					return 8;
			}
		}
		public static int KeySize(CipherAlgorithm alg)
		{
			switch (alg)
			{
				case CipherAlgorithm.Aes128:
					return 16;
				case CipherAlgorithm.Aes192:
					return 24;
				case CipherAlgorithm.Aes256:
					return 32;
				case CipherAlgorithm.Tdea:
					return 24;
			}
			return 0;
		}

		// Common padding and unpadding functions
		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int PAD_BytesBlock(byte[] output, int outlen, byte[] input, int inlen, int blklen, int options);
		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int PAD_UnpadBytes(byte[] output, int outlen, byte[] input, int inlen, int blklen, int options);
		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int PAD_HexBlock(StringBuilder szOutput, int nOutChars, string szInput, int blklen, int options);
		[DllImport("diCrPKI.dll", CharSet = CharSet.Ansi)]
		static extern int PAD_UnpadHex(StringBuilder szOutput, int nOutChars, string szInput, int blklen, int options);

		public static byte[] Pad(byte[] data, int blklen, Padding pad)
		{
			int padflags;
			if (pad == Padding.NoPad) return data;
			if (pad == Padding.Pkcs5)
				padflags = 0;
			else
				padflags = (int)pad;
			int n = PAD_BytesBlock(null, 0, data, data.Length, blklen, padflags);
			if (n <= 0) return new byte[0];
			byte[] b = new byte[n];
			n = PAD_BytesBlock(b, b.Length, data, data.Length, blklen, padflags);
			if (n <= 0) return new byte[0];
			return b;
		}

		public static string Pad(string dataHex, int blklen, Padding pad)
		{
			int padflags;
			if (pad == Padding.NoPad) return dataHex;
			if (pad == Padding.Pkcs5)
				padflags = 0;
			else
				padflags = (int)pad;
			int n = PAD_HexBlock(null, 0, dataHex, blklen, padflags);
			if (n <= 0) return String.Empty;
			StringBuilder sb = new StringBuilder(n);
			n = PAD_HexBlock(sb, n, dataHex, blklen, padflags);
			if (n <= 0) return String.Empty;
			return sb.ToString(0, n);
		}

		public static byte[] Unpad(byte[] data, int blklen, Padding pad)
		{	// Returns unchanged data on error or NoPad
			int padflags;
			if (pad == Padding.NoPad) return data;
			if (pad == Padding.Pkcs5)
				padflags = 0;
			else
				padflags = (int)pad;
			byte[] b = new byte[data.Length];
			int n = PAD_UnpadBytes(b, b.Length, data, data.Length, blklen, padflags);
			if (n < 0) return data;
			if (n == 0) return new byte[0];
			byte[] unpadded = new byte[n];
			Array.Copy(b, unpadded, n);
			return unpadded;
		}

		public static string Unpad(string dataHex, int blklen, Padding pad)
		{	// Returns unchanged data on error or NoPad
			int padflags;
			if (pad == Padding.NoPad) return dataHex;
			if (pad == Padding.Pkcs5)
				padflags = 0;
			else
				padflags = (int)pad;
			StringBuilder sb = new StringBuilder(dataHex.Length);
			int n = PAD_UnpadHex(sb, dataHex.Length, dataHex, blklen, padflags);
			if (n < 0) return dataHex;
			if (n == 0) return String.Empty;
			return sb.ToString(0, n);
		}
	}
}
