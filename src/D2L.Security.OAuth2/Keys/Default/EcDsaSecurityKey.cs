using System;
using System.IdentityModel.Tokens;
using System.Security.Cryptography;

namespace D2L.Security.OAuth2.Keys.Default {
	internal sealed partial class EcDsaSecurityKey : AsymmetricSecurityKey {

		private const int IDENTITY_MODEL_MIN_KEY_SIZE = 2048;

		private readonly ECDsa m_ECDsa;
		private readonly string m_signatureAlgorithm;
		private readonly string m_digestAlgorithm;

		public EcDsaSecurityKey(
			ECDsa ECDsa
		) {
			m_ECDsa = ECDsa;

			switch( m_ECDsa.KeySize ) {
				case 256: {
					m_signatureAlgorithm = SupportedSecurityAlgorithms.ECDsaSha256Signature;
					m_digestAlgorithm = CngAlgorithm.Sha256.Algorithm;
					break;
				}
				case 384: {
					m_signatureAlgorithm = SupportedSecurityAlgorithms.ECDsaSha384Signature;
					m_digestAlgorithm = CngAlgorithm.Sha384.Algorithm;
					break;
				}
				case 521: {
					m_signatureAlgorithm = SupportedSecurityAlgorithms.ECDsaSha512Signature;
					m_digestAlgorithm = CngAlgorithm.Sha512.Algorithm;
					break;
				}
				default: {
					throw new Exception( "Unknown key size" );
				}
			}
		}

		public string SignatureAlgorithm { get { return m_signatureAlgorithm; } }

		public string DigestAlgorithm { get { return m_digestAlgorithm; } }

		public override AsymmetricAlgorithm GetAsymmetricAlgorithm( string algorithm, bool privateKey ) {
			if( privateKey && !HasPrivateKey() ) {
				throw new CryptographicException( "No private key availabile" );
			}

			return m_ECDsa;
		}

		public override HashAlgorithm GetHashAlgorithmForSignature( string algorithm ) {
			return GetHashAlgorithmHelper( algorithm );
		}

		public override AsymmetricSignatureDeformatter GetSignatureDeformatter( string algorithm ) {
			var result = new EcDsaSignatureDeformatter();
			result.SetKey( m_ECDsa );
			result.SetHashAlgorithm( algorithm );
			return result;
		}

		public override AsymmetricSignatureFormatter GetSignatureFormatter( string algorithm ) {
			var result = new EcDsaSignatureFormatter();
			result.SetKey( m_ECDsa );
			result.SetHashAlgorithm( algorithm );
			return result;
		}

		public override bool HasPrivateKey() {
			return true;
		}

		public override byte[] DecryptKey( string algorithm, byte[] keyData ) {
			throw new NotImplementedException();
		}

		public override byte[] EncryptKey( string algorithm, byte[] keyData ) {
			throw new NotImplementedException();
		}

		public override bool IsAsymmetricAlgorithm( string algorithm ) {
			if( String.IsNullOrWhiteSpace( algorithm ) ) {
				throw new ArgumentNullException( "algorithm" );
			}

			switch( algorithm ) {
				case SupportedSecurityAlgorithms.ECDsaSha256Signature:
				case SupportedSecurityAlgorithms.ECDsaSha384Signature:
				case SupportedSecurityAlgorithms.ECDsaSha512Signature:
					return true;
				default:
					throw new Exception( string.Format( "Unsupported algorithm '{0}", algorithm ) );
			}
		}

		public override bool IsSupportedAlgorithm( string algorithm ) {
			if( String.IsNullOrWhiteSpace( algorithm ) ) {
				throw new ArgumentNullException( "algorithm" );
			}

			switch( algorithm ) {
				case SupportedSecurityAlgorithms.ECDsaSha256Signature:
				case SupportedSecurityAlgorithms.ECDsaSha384Signature:
				case SupportedSecurityAlgorithms.ECDsaSha512Signature:
					return true;
				default:
					return false;
			}
		}

		public override bool IsSymmetricAlgorithm( string algorithm ) {
			if( String.IsNullOrWhiteSpace( algorithm ) ) {
				throw new ArgumentNullException( "algorithm" );
			}

			switch( algorithm ) {
				case SupportedSecurityAlgorithms.ECDsaSha256Signature:
				case SupportedSecurityAlgorithms.ECDsaSha384Signature:
				case SupportedSecurityAlgorithms.ECDsaSha512Signature:
					return false;
				default:
					throw new Exception( string.Format( "Unsupported algorithm '{0}", algorithm ) );
			}
		}

		public override int KeySize {
			get {
				// This should be m_ECDsa.KeySize, but that is small, and microsoft complains
				return IDENTITY_MODEL_MIN_KEY_SIZE;
			}
		}

		private static HashAlgorithm GetHashAlgorithmHelper( string algorithm ) {
			if( String.IsNullOrWhiteSpace( algorithm ) ) {
				throw new ArgumentNullException( "algorithm" );
			}

			var maybeAlg = CryptoConfig.CreateFromName( algorithm ) as HashAlgorithm;
			if( maybeAlg != null ) {
				return maybeAlg;
			}

			switch( algorithm ) {
				case SupportedSecurityAlgorithms.ECDsaSha256Signature:
					return SHA256.Create();
				case SupportedSecurityAlgorithms.ECDsaSha384Signature:
					return SHA384.Create();
				case SupportedSecurityAlgorithms.ECDsaSha512Signature:
					return SHA512.Create();
				default:
					throw new Exception( string.Format( "Unsupported algorithm '{0}", algorithm ) );
			}
		}
	}
}
