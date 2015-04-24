using System;
using System.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Text;

using D2L.Security.OAuth2.Utilities;

namespace D2L.Security.OAuth2.Validation.Token.Tests.Utilities {
	internal static class TestTokenProvider {

		private static readonly DateTime UNIX_EPOCH_BEGINNING = new DateTime( 1970, 1, 1, 0, 0, 0, DateTimeKind.Utc );

		internal static string MakeJwt( string algorithm, string tokenType, string payload, RSAParameters rsaParams ) {
			byte[] header = MakeHeader( algorithm, tokenType );

			byte[] payloadBytes = Encoding.UTF8.GetBytes( payload );

			byte[] signature;
			using( RSACryptoServiceProvider rsaService = new RSACryptoServiceProvider() ) {
				rsaService.PersistKeyInCsp = false;
				rsaService.ImportParameters( rsaParams );
				string oid = CryptoConfig.MapNameToOID( "SHA256" );

				string base64UrlHeader = Base64UrlEncoder.Encode( header );
				string base64UrlPayload = Base64UrlEncoder.Encode( payloadBytes );
				signature = rsaService.SignData( Encoding.UTF8.GetBytes( base64UrlHeader + "." + base64UrlPayload ), oid );
			}

			string jwt = String.Format( 
				"{0}.{1}.{2}",
				Base64UrlEncoder.Encode( header ),
				Base64UrlEncoder.Encode( payloadBytes ),
				Base64UrlEncoder.Encode( signature ) 
				);

			return jwt;
		}

		internal static string MakePayload( string issuer, string scope, DateTime expiry ) {
			long expiryInSeconds = GetSecondsRelativeToUnixEpoch( expiry );
			return MakePayload( issuer, scope, expiryInSeconds );
		}

		internal static string MakePayload( string issuer, string scope, TimeSpan expiryFromNow ) {
			DateTime expiry = DateTime.UtcNow + expiryFromNow;
			long expiryInSeconds = GetSecondsRelativeToUnixEpoch( expiry );
			return MakePayload( issuer, scope, expiryInSeconds );
		}

		private static string MakePayload( string issuer, string scope, long expiryInSeconds ) {
			StringBuilder payloadBuilder = new StringBuilder( "{\"client_id\":\"lores_manager_client\",\"scope\":\"" );
			payloadBuilder.Append( scope );
			payloadBuilder.Append( "\",\"iss\":\"" );
			payloadBuilder.Append( issuer );
			payloadBuilder.Append( "\",\"aud\":\"some_audience\",\"exp\":" );
			payloadBuilder.Append( expiryInSeconds );
			payloadBuilder.Append( ",\"nbf\":1421352874}" );

			return payloadBuilder.ToString();
		}

		internal static RSAParameters CreateRSAParams() {
			using( RSACryptoServiceProvider rsaService = new RSACryptoServiceProvider( 2048 ) ) {
				rsaService.PersistKeyInCsp = false;
				RSAParameters rsaParams = rsaService.ExportParameters( true );
				return rsaParams;
			}
		}

		private static long GetSecondsRelativeToUnixEpoch( DateTime expiry ) {
			TimeSpan timeToExpireSinceUnixEpoch = expiry - UNIX_EPOCH_BEGINNING;
			long seconds = (long)timeToExpireSinceUnixEpoch.TotalSeconds;
			return seconds;
		}

		private static byte[] MakeHeader( string alg, string typ ) {
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

			return Encoding.UTF8.GetBytes( header.ToString() );
		}
	}
}
