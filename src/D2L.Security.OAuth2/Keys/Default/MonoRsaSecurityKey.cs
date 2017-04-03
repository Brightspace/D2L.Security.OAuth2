using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace D2L.Security.OAuth2.Keys.Default {
#if __MonoCS__ || MONO
	internal sealed class MonoRsaSecurityKey : AsymmetricSecurityKey {

		private readonly RSA m_rsa;

		public MonoRsaSecurityKey( RSA rsa ) {
			m_rsa = rsa;
		}

		public override int KeySize {
			get { return m_rsa.KeySize; }
		}

		public override byte[] DecryptKey( string algorithm, byte[] keyData ) {
			throw new NotImplementedException();
		}

		public override byte[] EncryptKey( string algorithm, byte[] keyData ) {
			throw new NotImplementedException();
		}

		public override bool IsAsymmetricAlgorithm( string algorithm ) {
			if (String.IsNullOrWhiteSpace(algorithm)) {
				throw new ArgumentNullException( "algorithm" );
			}

			switch ( algorithm ) {
				case SecurityAlgorithms.RsaSha1Signature:
				case SecurityAlgorithms.RsaSha256Signature:
				case SecurityAlgorithms.RsaOaepKeyWrap:
				case SecurityAlgorithms.RsaV15KeyWrap:
					return true;
			}

			throw new NotSupportedException( $"Unsupported algorithm '{algorithm}'" );
		}

		public override bool IsSupportedAlgorithm( string algorithm ) {
			if (String.IsNullOrWhiteSpace(algorithm)) {
				throw new ArgumentNullException( "algorithm" );
			}

			switch (algorithm) {
				case SecurityAlgorithms.RsaSha1Signature:
				case SecurityAlgorithms.RsaSha256Signature:
				case SecurityAlgorithms.RsaOaepKeyWrap:
				case SecurityAlgorithms.RsaV15KeyWrap:
					return true;
			}

			return false;
		}

		public override bool IsSymmetricAlgorithm( string algorithm ) {
			if (String.IsNullOrWhiteSpace(algorithm)) {
				throw new ArgumentNullException( "algorithm" );
			}

			switch ( algorithm ) {
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
			}

			throw new NotSupportedException( $"Unsupported algorithm '{algorithm}'" );
		}

		public override AsymmetricAlgorithm GetAsymmetricAlgorithm( string algorithm, bool privateKey ) {
			if( privateKey && !HasPrivateKey() ) {
				throw new CryptographicException( "No private key availabile" );
			}

			return m_rsa;
		}

		public override HashAlgorithm GetHashAlgorithmForSignature( string algorithm ) {
			if( String.IsNullOrWhiteSpace( algorithm ) ) {
				throw new ArgumentNullException( "algorithm" );
			}

			var maybeAlg = CryptoConfig.CreateFromName( algorithm ) as HashAlgorithm;
			if( maybeAlg != null ) {
				return maybeAlg;
			}
			switch( algorithm ) {
				case SecurityAlgorithms.RsaSha1Signature:
					return SHA1.Create();
				case SecurityAlgorithms.RsaSha256Signature:
					return SHA256.Create();
				default:
					throw new NotSupportedException( $"{algorithm} is not supported" );
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
			if( rcsp != null ) {
				return !rcsp.PublicOnly;
			}

			try {
				rcsp.ExportParameters( true );
				return true;
			} catch( CryptographicException ) {
				return false;
			}
		}

	}
#endif

}