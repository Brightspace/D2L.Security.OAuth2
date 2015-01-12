using System;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Text;
using System.Web;
using D2L.Security.AuthTokenValidation.TokenValidation;
using Newtonsoft.Json;

namespace D2L.Security.AuthTokenValidation.Default {

	internal sealed class AuthTokenValidator : IAuthTokenValidator {

		private readonly IJWTValidator m_validator;

		public AuthTokenValidator(
			IJWTValidator validator
			) {
			m_validator = validator;
		}

		Principal IAuthTokenValidator.VerifyAndDecode( HttpRequest request ) {

			IAuthTokenValidator @this = this;

			string tokenFromCookie = GetTokenFromCookie( request );
			string tokenFromAuthHeader = GetTokenFromAuthHeader( request );

			if( tokenFromCookie != null && tokenFromAuthHeader != null ) {
				throw new AuthorizationException( "Token cannot be provided in header and cookie" );
			}

			return @this.VerifyAndDecode( tokenFromCookie ?? tokenFromAuthHeader );
		}

		Principal IAuthTokenValidator.VerifyAndDecode( string jwt ) {

			const int HEADER_INDEX = 0;
			const int PAYLOAD_INDEX = 1;
			const int SIGNATURE_INDEX = 2;

			string[] parts = GetTokenParts( jwt );

			string headerJson = UnencodeBase64Url( parts[ HEADER_INDEX ] );
			VerifyHeader( headerJson );

			byte[] payloadBytes = Encoding.UTF8.GetBytes( UnencodeBase64Url( parts[ PAYLOAD_INDEX ] ) );
			byte[] signature = Encoding.UTF8.GetBytes( parts[ SIGNATURE_INDEX ] );
			
			IClaimsPrincipal claimsPrincipal = m_validator.Validate( jwt );
			return GetPrincipal( claimsPrincipal );
		}

		internal static string GetTokenFromCookie( HttpRequest request ) {

			HttpCookie cookie = request.Cookies.Get( "d2lApi" );
			string authToken = null;
			if( cookie != null ) {
				authToken = cookie.Value;
			}
			return authToken;
		}

		internal static string GetTokenFromAuthHeader( HttpRequest request ) {

			const string AUTH_HEADER_VALUE_PREFIX = "Bearer ";
			string authorization = request.Headers.Get( "Authorization" );
			string authToken = null;
			if( authorization != null && authorization.StartsWith( AUTH_HEADER_VALUE_PREFIX ) ) {
				authToken = authorization.Substring( AUTH_HEADER_VALUE_PREFIX.Length );
			}
			return authToken;
		}

		internal static string[] GetTokenParts( string jwt ) {

			string[] parts = jwt.Split( '.' );
			if( parts.Length != 3 ) {
				throw new AuthorizationException( "Invalid token format" );
			}
			
			if ( parts.Any( part => part == string.Empty ) ) {
				throw new AuthorizationException( "Empty JWT segment" );
			}

			return parts;
		}

		internal static string UnencodeBase64Url( string b64 ) {

			string result = b64
				.Replace( '-', '+' )
				.Replace( '_', '/' )
				.PadRight( b64.Length + ( 4 - b64.Length % 4 ) % 4, '=' );

			result = Encoding.UTF8.GetString( Convert.FromBase64String( result ) );

			return result;
		}

		internal static void VerifyHeader( string headerJson ) {

			JwtHeader header = JsonConvert.DeserializeObject<JwtHeader>( headerJson );

			if( header.Alg != "RS256" ) {
				throw new AuthorizationException( string.Format( "Unsupported encryption scheme '{0}'", header.Alg ) );
			}
			if( header.Typ != "JWT" ) {
				throw new AuthorizationException( string.Format( "Unsupported token type '{0}'", header.Alg ) );
			}
		}

		internal static Principal GetPrincipal( IClaimsPrincipal claimsPrincipal ) {

			Principal principal = new Principal(
				-1337,
				"DUMMY TENANT ID!!",
				"DUMMY XSRF TOKEN!!",
				null
				);

			return principal;
		}
	}
}