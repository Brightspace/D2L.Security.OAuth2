using System.Collections.Generic;
using System.Linq;
using System.Web;
using D2L.Security.AuthTokenValidation.TokenValidation;

namespace D2L.Security.AuthTokenValidation.Default {

	internal sealed class AuthTokenValidator : IAuthTokenValidator {

		private readonly IJWTValidator m_validator;

		public AuthTokenValidator(
			IJWTValidator validator
			) {
			m_validator = validator;
		}

		IGenericPrincipal IAuthTokenValidator.VerifyAndDecode( HttpRequest request ) {

			IAuthTokenValidator @this = this;

			string tokenFromCookie = GetTokenFromCookie( request );
			string tokenFromAuthHeader = GetTokenFromAuthHeader( request );

			if( tokenFromCookie != null && tokenFromAuthHeader != null ) {
				throw new AuthorizationException( "Token cannot be provided in the header and cookie" );
			}

			return @this.VerifyAndDecode( tokenFromCookie ?? tokenFromAuthHeader );
		}

		IGenericPrincipal IAuthTokenValidator.VerifyAndDecode( string jwt ) {
			IValidatedJWT validatedJWT = m_validator.Validate( jwt );
			return GetPrincipal( validatedJWT );
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

		internal static Principal GetPrincipal( IValidatedJWT validatedJWT ) {

			string scopeClaimValue = validatedJWT.Claims
				.Where( x => x.Type == "scope" )
				.Select( x => x.Value )
				.First();
			HashSet<string> scopes = new HashSet<string>( 
				scopeClaimValue.Split( ',' )
				);

			Principal principal = new Principal(
				-1337,
				"DUMMY TENANT ID!!",
				"DUMMY XSRF TOKEN!!",
				scopes
				);

			return principal;
		}
	}
}