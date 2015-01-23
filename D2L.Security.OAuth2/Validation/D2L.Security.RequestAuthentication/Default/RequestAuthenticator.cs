using System.Net.Http;
using System.Web;
using D2L.Security.AuthTokenValidation;

namespace D2L.Security.RequestAuthentication.Default {
	internal sealed class RequestAuthenticator : IRequestAuthenticator {

		private const string COOKIE_NAME = "d2lApi";

		private readonly IAuthTokenValidator m_tokenValidator;

		internal RequestAuthenticator( IAuthTokenValidator tokenValidator ) {
			m_tokenValidator = tokenValidator;
		}

		AuthenticationResult IRequestAuthenticator.AuthenticateAndExtract( HttpRequestMessage request, out ID2LPrincipal principal ) {
			string cookie = request.GetCookieValue( COOKIE_NAME );
			string bearerToken = request.GetBearerTokenValue();
			string xsrfToken = request.GetXsrfValue();

			return TryAuthenticate( cookie, xsrfToken, bearerToken, out principal );
		}

		AuthenticationResult IRequestAuthenticator.AuthenticateAndExtract( HttpRequest request, out ID2LPrincipal principal ) {
			string cookie = request.GetCookieValue( COOKIE_NAME );
			string bearerToken = request.GetBearerTokenValue();
			string xsrfToken = request.GetXsrfValue();

			return TryAuthenticate( cookie, xsrfToken, bearerToken, out principal );
		}

		private AuthenticationResult TryAuthenticate( 
			string cookie, 
			string xsrfHeader, 
			string bearerToken, 
			out ID2LPrincipal principal 
			) {

			if( cookie == null && bearerToken == null ) {
				principal = null;
				return AuthenticationResult.Anonymous;
			}

			if( cookie != null && bearerToken != null ) {
				principal = null;
				return AuthenticationResult.TokenLocationConflict;
			}

			bool isBrowserUser = cookie != null;

			string token = bearerToken ?? cookie;

			IGenericPrincipal claims;
			ValidationResult validationResult = m_tokenValidator.VerifyAndDecode( token, out claims );

			if( validationResult == ValidationResult.TokenExpired ) {
				principal = null;
				return AuthenticationResult.Expired;
			}

			bool xsrfSafe = false;
			if( isBrowserUser && xsrfHeader != null ) {
				if( claims.XsrfToken != xsrfHeader ) {
					principal = null;
					return AuthenticationResult.BadXsrf;
				}

				xsrfSafe = true;
			}

			principal = new D2LPrincipal( xsrfSafe );
			return AuthenticationResult.Success;
		}
	}
}
