using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using Newtonsoft.Json;

namespace D2L.Security.AuthTokenValidation.Default {

	internal sealed class AuthTokenValidator : IAuthTokenValidator {

		private readonly IAuthServerPublicKeyProvider m_authServerPublicKeyProvider;

		public AuthTokenValidator(
			IAuthServerPublicKeyProvider authServerPublicKeyProvider
			) {
			m_authServerPublicKeyProvider = authServerPublicKeyProvider;
		}

		public Principal VerifyAndDecode( HttpRequest request ) {

			string tokenFromCookie = GetTokenFromCookie( request );
			string tokenFromAuthHeader = GetTokenFromAuthHeader( request );

			if( tokenFromCookie != null && tokenFromAuthHeader != null ) {
				throw new AuthorizationException( "Token cannot be provided in header and cookie" );
			}

			return VerifyAndDecode( tokenFromCookie ?? tokenFromAuthHeader );
		}

		public Principal VerifyAndDecode( string jwt ) {

			const int HEADER_INDEX = 0;
			const int PAYLOAD_INDEX = 1;
			const int SIGNATURE_INDEX = 2;

			string[] parts = GetTokenParts( jwt );

			string headerJson = UnencodeBase64Url( parts[ HEADER_INDEX ] );
			VerifyHeader( headerJson );

			byte[] payloadBytes = Encoding.UTF8.GetBytes( UnencodeBase64Url( parts[ PAYLOAD_INDEX ] ) );
			byte[] signature = Encoding.UTF8.GetBytes( parts[ SIGNATURE_INDEX ] );

			VerifySignature( payloadBytes, signature );

			string payload = Encoding.UTF8.GetString( payloadBytes );

			return GetPrincipal( payload );
		}

		private static string GetTokenFromCookie( HttpRequest request ) {

			HttpCookie cookie = request.Cookies.Get( "d2lApi" );
			string authToken = null;
			if( cookie != null ) {
				authToken = cookie.Value;
			}
			return authToken;
		}

		private static string GetTokenFromAuthHeader( HttpRequest request ) {

			const string AUTH_HEADER_VALUE_PREFIX = "Bearer ";
			string authorization = request.Headers.Get( "Authorization" );
			string authToken = null;
			if( authorization != null && authorization.StartsWith( AUTH_HEADER_VALUE_PREFIX ) ) {
				authToken = authorization.Substring( AUTH_HEADER_VALUE_PREFIX.Length );
			}
			return authToken;
		}

		private string[] GetTokenParts( string jwt ) {

			string[] parts = jwt.Split( '.' );
			if( parts.Length != 3 ) {
				throw new AuthorizationException( "Invalid token format" );
			}
			return parts;
		}

		private static string UnencodeBase64Url( string b64 ) {
			string result = b64
				.Replace( '-', '+' )
				.Replace( '_', '/' )
				.PadRight( b64.Length + ( 4 - b64.Length % 4 ) % 4, '=' );

			result = Encoding.UTF8.GetString( Convert.FromBase64String( result ) );

			return result;
		}

		private void VerifyHeader( string headerJson ) {
			JwtHeader header = JsonConvert.DeserializeObject<JwtHeader>( headerJson );

			if( header.Alg != "RS256" ) {
				throw new AuthorizationException( string.Format( "Unsupported encryption scheme '{0}'", header.Alg ) );
			}
			if( header.Typ != "JWT" ) {
				throw new AuthorizationException( string.Format( "Unsupported token type '{0}'", header.Alg ) );
			}
		}

		private void VerifySignature( byte[] payloadBytes, byte[] signature ) {

			using( ECDsaCng signer = new ECDsaCng( m_authServerPublicKeyProvider.Get() ) ) {
				if( !signer.VerifyData( payloadBytes, signature ) ) {
					throw new AuthorizationException( "Signature comparison failed" );
				}
			}
		}

		private Principal GetPrincipal( string payload ) {

			Principal principal = JsonConvert.DeserializeObject<Principal>( payload );

			HashSet<string> scopes = principal.Scopes ?? new HashSet<string>();
			if( principal.IsBrowserUser ) {
				scopes.Add( "*" );
			}

			return principal;
		}
	}
}