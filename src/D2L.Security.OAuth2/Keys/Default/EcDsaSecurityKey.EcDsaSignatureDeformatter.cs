using System;
using System.Security.Cryptography;

namespace D2L.Security.OAuth2.Keys.Default {
	partial class EcDsaSecurityKey {
		internal sealed class EcDsaSignatureDeformatter : AsymmetricSignatureDeformatter {

			private ECDsa m_key;
			private HashAlgorithm m_hashAlgorithm;

			public override bool VerifySignature( byte[] rgbHash, byte[] rgbSignature ) {
				if( rgbHash == null ) {
					throw new ArgumentNullException( "rgbHash" );
				}

				if( m_key == null ) {
					throw new Exception( "Must initialize key before verifying a signature" );
				}

				if( m_hashAlgorithm == null ) {
					throw new Exception( "Must initialize hash algorithm before verifying a signature" );
				}

				bool valid = m_key.VerifyHash( rgbHash, rgbSignature );
				return valid;
			}

			public override void SetHashAlgorithm( string algorithm ) {
				m_hashAlgorithm = GetHashAlgorithmHelper( algorithm );
			}

			public override void SetKey( AsymmetricAlgorithm key ) {
				if( key == null ) {
					throw new ArgumentNullException( "key" );
				}

				if( key is ECDsa ) {
					m_key = key as ECDsa;
					return;
				}

				throw new NotImplementedException();
			}

		}
	}
}
