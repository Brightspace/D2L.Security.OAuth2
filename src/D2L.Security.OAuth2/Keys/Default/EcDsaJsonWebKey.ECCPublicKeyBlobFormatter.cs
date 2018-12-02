using System;
using System.IdentityModel.Tokens;

namespace D2L.Security.OAuth2.Keys.Default {
	partial class EcDsaJsonWebKey {
		private sealed class ECCPublicKeyBlobFormatter {

			internal static readonly ECCPublicKeyBlobFormatter Instance = new ECCPublicKeyBlobFormatter();

			internal enum KeyBlobMagicNumber {
				ECDSA_PUBLIC_P256 = 0x31534345,
				ECDSA_PUBLIC_P384 = 0x33534345,
				ECDSA_PUBLIC_P521 = 0x35534345
			};

			internal enum KeySize {
				P256 = 256,
				P384 = 384,
				P521 = 521
			};

			internal byte[] BuildECCPublicBlob( EcDsaJsonWebKey jwk ) {
				KeyBlobMagicNumber magic;
				KeySize keySize;
				switch( jwk.m_curve ) {
					case "P-256": {
							magic = KeyBlobMagicNumber.ECDSA_PUBLIC_P256;
							keySize = KeySize.P256;
							break;
						}
					case "P-384": {
							magic = KeyBlobMagicNumber.ECDSA_PUBLIC_P384;
							keySize = KeySize.P384;
							break;
						}
					case "P-521": {
							magic = KeyBlobMagicNumber.ECDSA_PUBLIC_P521;
							keySize = KeySize.P521;
							break;
						}
					default: {
							throw new Exception( "Unknown curve: " + jwk.m_curve );
						}
				}

				byte[] x = Base64UrlEncoder.DecodeBytes( jwk.m_x );
				x = FillBytes( x, ( int )keySize );

				byte[] y = Base64UrlEncoder.DecodeBytes( jwk.m_y );
				y = FillBytes( y, ( int )keySize );

				// Finally, lay out the structure itself
				byte[] blob = new byte[ 2 * sizeof( int ) + x.Length + y.Length ];

				int offset = 0;
				Func<int, int> increaseOffset = ( size ) => {
					offset += size;
					return size;
				};

				Buffer.BlockCopy( BitConverter.GetBytes( ( int )magic ), 0, blob, offset, increaseOffset( sizeof( int ) ) );
				Buffer.BlockCopy( BitConverter.GetBytes( x.Length ), 0, blob, offset, increaseOffset( sizeof( int ) ) );
				Buffer.BlockCopy( x, 0, blob, offset, increaseOffset( x.Length ) );
				Buffer.BlockCopy( y, 0, blob, offset, increaseOffset( y.Length ) );

				return blob;
			}

			internal void ParsePublicBlob( byte[] blob, out string crv, out string x, out string y ) {
				if( blob.Length < 2 * sizeof( int ) ) {
					throw new Exception( "blob is definitely invalid" );
				}

				int offset = 0;
				Func<int, int> increaseOffset = ( size ) => {
					var oldOffset = offset;
					offset += size;
					return oldOffset;
				};
				KeyBlobMagicNumber magic = ( KeyBlobMagicNumber )BitConverter.ToUInt32( blob, increaseOffset( sizeof( uint ) ) );
				int byteLength = ( int )BitConverter.ToUInt32( blob, increaseOffset( sizeof( uint ) ) );

				if( ( blob.Length - offset ) != byteLength * 2 ) {
					throw new Exception( "expected equal length curve parameters to remain" );
				}

				byte[] xBytes = new byte[ byteLength ];
				Buffer.BlockCopy( blob, increaseOffset( xBytes.Length ), xBytes, 0, xBytes.Length );

				byte[] yBytes = new byte[ byteLength ];
				Buffer.BlockCopy( blob, increaseOffset( yBytes.Length ), yBytes, 0, yBytes.Length );

				switch( magic ) {
					case KeyBlobMagicNumber.ECDSA_PUBLIC_P256: {
							crv = "P-256";
							break;
						}
					case KeyBlobMagicNumber.ECDSA_PUBLIC_P384: {
							crv = "P-384";
							break;
						}
					case KeyBlobMagicNumber.ECDSA_PUBLIC_P521: {
							crv = "P-521";
							break;
						}
					default: {
							throw new Exception( "Unknown magic number " + magic );
						}
				}

				x = Base64UrlEncoder.Encode( xBytes );
				y = Base64UrlEncoder.Encode( yBytes );
			}

			private byte[] FillBytes( byte[] bytes, int size ) {
				int byteLength = ( size / 8 ) + ( size % 8 == 0 ? 0 : 1 );
				if( bytes.Length == byteLength ) {
					return bytes;
				}

				byte[] filledBytes = new byte[ byteLength ];
				var srcOffset = Math.Max( 0, bytes.Length - filledBytes.Length );
				int dstOffset = Math.Max( 0, filledBytes.Length - bytes.Length );
				int count = Math.Min( filledBytes.Length, bytes.Length );
				Buffer.BlockCopy( bytes, srcOffset, filledBytes, dstOffset, count );

				return filledBytes;
			}

		}
	}
}
