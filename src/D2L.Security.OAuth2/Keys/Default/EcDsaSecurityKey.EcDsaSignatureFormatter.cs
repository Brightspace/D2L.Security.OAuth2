using System;
using System.Security.Cryptography;

namespace D2L.Security.OAuth2.Keys.Default {
	partial class EcDsaSecurityKey {
		internal sealed class EcDsaSignatureFormatter : AsymmetricSignatureFormatter {

			private ECDsa m_key;
			private HashAlgorithm m_hashAlgorithm;

			public override byte[] CreateSignature( byte[] rgbHash ) {
				if( rgbHash == null ) {
					throw new ArgumentNullException( "rgbHash" );
				}

				if( m_key == null ) {
					throw new Exception( "Must initialize key before creating a signature" );
				}

				if( m_hashAlgorithm == null ) {
					throw new Exception( "Must initialize hash algorithm before creating a signature" );
				}

				byte[] signature = m_key.SignHash( rgbHash );
				return signature;
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
