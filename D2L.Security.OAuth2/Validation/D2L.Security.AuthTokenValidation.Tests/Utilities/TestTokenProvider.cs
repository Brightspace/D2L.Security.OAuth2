using System;
using System.Security.Cryptography;
using System.Text;

namespace D2L.Security.AuthTokenValidation.Tests.Utilities {
	internal static class TestTokenProvider {

		internal static string MakeJwt( string alg, string typ, string payload, RSAParameters rsaKeys ) {
			StringBuilder header = new StringBuilder( "{" );
			if( alg != null ) {
				header.Append( "\"alg\":\"" );
				header.Append( alg );
				header.Append( "\"" );
			}
			if( typ != null ) {
				if( alg != null ) {
					header.Append( ',' );
				}
				header.Append( "\"typ\":\"" );
				header.Append( typ );
				header.Append( "\"" );
			}
			header.Append( '}' );

			byte[] signature;

			using( RSACryptoServiceProvider rsa = new RSACryptoServiceProvider() ) {
				rsa.ImportParameters( rsaKeys );
				signature = rsa.SignData( Encoding.UTF8.GetBytes( payload ), CryptoConfig.MapNameToOID( "SHA256" ) );
			}

			string jwt = String.Format( 
				"{0}.{1}.{2}",
				Base64Url( header.ToString() ),
				Base64Url( payload ),
				Base64Url( signature ) 
				);

			return jwt;
		}

		internal static RSAParameters CreateRSAKey() {
			using( RSACryptoServiceProvider rsa = new RSACryptoServiceProvider( 2048 ) ) {
				rsa.PersistKeyInCsp = false;
				RSAParameters rsaKeys = rsa.ExportParameters( true );
				return rsaKeys;
			}
		}

		private static string Base64Url( string s ) {
			return Base64Url( Encoding.UTF8.GetBytes( s ) );
		}

		private static string Base64Url( byte[] s ) {
			return Convert
				.ToBase64String( s )
				.Replace( '+', '-' )
				.Replace( '/', '_' )
				.Trim( '=' );
		}

	}
}
