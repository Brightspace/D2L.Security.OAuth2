using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace D2L.Security.OAuth2.Keys.Default {

	internal sealed class MonoRsaSecurityKey : AsymmetricSecurityKey {

		private RSA m_rsa;

		public MonoRsaSecurityKey( RSA rsa ) {
			m_rsa = rsa;
		}

		public override byte[] DecryptKey( string algorithm, byte[] keyData ) {
			throw new NotImplementedException();
		}

		public override byte[] EncryptKey( string algorithm, byte[] keyData ) {
			throw new NotImplementedException();
		}

		public override bool IsAsymmetricAlgorithm( string algorithm ) {
			switch (algorithm) {
			case SecurityAlgorithms.DsaSha1Signature:
			case SecurityAlgorithms.RsaSha1Signature:
			case SecurityAlgorithms.RsaSha256Signature:
			case SecurityAlgorithms.RsaOaepKeyWrap:
			case SecurityAlgorithms.RsaV15KeyWrap:
				return true;
			default:
				return false;
			}
		}

		public override bool IsSupportedAlgorithm( string algorithm ) {
			throw new NotImplementedException();
		}

		public override bool IsSymmetricAlgorithm( string algorithm ) {
			switch (algorithm) {
			case SecurityAlgorithms.DsaSha1Signature:
			case SecurityAlgorithms.RsaSha1Signature:
			case SecurityAlgorithms.RsaSha256Signature:
			case SecurityAlgorithms.RsaOaepKeyWrap:
			case SecurityAlgorithms.RsaV15KeyWrap:
				return false;
			case SecurityAlgorithms.HmacSha1Signature:
			case SecurityAlgorithms.HmacSha256Signature:
			case SecurityAlgorithms.Aes128Encryption:
			case SecurityAlgorithms.Aes192Encryption:
			case SecurityAlgorithms.DesEncryption:
			case SecurityAlgorithms.Aes256Encryption:
			case SecurityAlgorithms.TripleDesEncryption:
			case SecurityAlgorithms.Aes128KeyWrap:
			case SecurityAlgorithms.Aes192KeyWrap:
			case SecurityAlgorithms.Aes256KeyWrap:
			case SecurityAlgorithms.TripleDesKeyWrap:
			case SecurityAlgorithms.Psha1KeyDerivation:
			case SecurityAlgorithms.Psha1KeyDerivationDec2005:
				return true;
			default:
				return false;
			}
		}

		public override int KeySize {
			get { return m_rsa.KeySize; }
		}

		public override AsymmetricAlgorithm GetAsymmetricAlgorithm( string algorithm, bool privateKey ) {
			if (privateKey && !HasPrivateKey()) {
				throw new CryptographicException("No private key availabile");
			}

			return m_rsa;
		}

		public override HashAlgorithm GetHashAlgorithmForSignature( string algorithm ) {
			if (String.IsNullOrWhiteSpace(algorithm)) {
				throw new ArgumentNullException("algorithm");
			}

			var maybeAlg = CryptoConfig.CreateFromName(algorithm) as HashAlgorithm;
			if (maybeAlg != null) {
				return maybeAlg;
			}
			switch (algorithm) {
			case SecurityAlgorithms.RsaSha1Signature:
					return SHA1.Create();
			case SecurityAlgorithms.RsaSha256Signature:
					return SHA256.Create();
			default:
				throw new Exception(string.Format("Unsupported algorithm '{0}", algorithm));
			}

		}

		public override AsymmetricSignatureDeformatter GetSignatureDeformatter( string algorithm ) {
			return new RSAPKCS1SignatureDeformatter( m_rsa );
		}

		public override AsymmetricSignatureFormatter GetSignatureFormatter( string algorithm ) {
			return new RSAPKCS1SignatureFormatter( m_rsa );
		}

		public override bool HasPrivateKey() {
			RSACryptoServiceProvider rcsp = m_rsa as RSACryptoServiceProvider;
			if (rcsp != null)
				return !rcsp.PublicOnly;
			try {
				rcsp.ExportParameters(true);
				return true;
			} catch (CryptographicException) {
				return false;
			}
		}

	}
}
