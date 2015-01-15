using System;
using System.Security.Cryptography;
using System.Text;

namespace D2L.Security.AuthTokenValidation.Tests.Utilities {
	internal static class TestTokenProvider {

		private static string MakeHeader( string alg, string typ ) {
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

			return header.ToString();
		}

		internal static string MakeJwt( string alg, string typ, string payload, RSAParameters rsaParams ) {
			string header = MakeHeader( alg, typ );

			byte[] signature;
			using( RSACryptoServiceProvider rsaService = new RSACryptoServiceProvider() ) {
				rsaService.ImportParameters( rsaParams );
				byte[] payloadBytes = Encoding.UTF8.GetBytes( payload );
				string oid = CryptoConfig.MapNameToOID( "SHA256" );
				signature = rsaService.SignData( Encoding.UTF8.GetBytes(Base64Url(header) + "." + Base64Url(payload)), oid );
			}

			string jwt = String.Format( 
				"{0}.{1}.{2}",
				Base64Url( header.ToString() ),
				Base64Url( payload ),
				Base64Url( signature ) 
				);

			return jwt;
		}

		internal static RSAParameters CreateRSAParams() {
			using( RSACryptoServiceProvider rsaService = new RSACryptoServiceProvider( 2048 ) ) {
				rsaService.PersistKeyInCsp = false;
				RSAParameters rsaParams = rsaService.ExportParameters( true );
				return rsaParams;
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
