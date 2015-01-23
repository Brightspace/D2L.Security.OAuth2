using System.Linq;
using System.Net.Http;
using System.Web;
using D2L.Security.AuthTokenValidation;

namespace D2L.Security.RequestAuthentication.Default {
	internal sealed class RequestAuthenticator : IRequestAuthenticator {

		private const string COOKIE_NAME = "d2lApi";
		private const string AUTH_HEADER_PREFIX = "Bearer ";
		private const string XSRF_HEADER = "X-Csrf-Token";

		private readonly IAuthTokenValidator m_tokenValidator;

		internal RequestAuthenticator( IAuthTokenValidator tokenValidator ) {
			m_tokenValidator = tokenValidator;
		}

		AuthenticationResult IRequestAuthenticator.AuthenticateAndExtract( HttpRequestMessage request, out ID2LPrincipal principal ) {
			string cookie = request.GetCookieValue( COOKIE_NAME );

			string bearerToken = null;
			var authHeader = request.Headers.Authorization;
			if( authHeader != null && authHeader.Scheme == "Bearer" ) {
				bearerToken = authHeader.Parameter;
			}

			string xsrfToken = request.Headers.GetValues( XSRF_HEADER ).FirstOrDefault();

			return TryAuthenticate( cookie, xsrfToken, bearerToken, out principal );
		}

		AuthenticationResult IRequestAuthenticator.AuthenticateAndExtract( HttpRequest request, out ID2LPrincipal principal ) {
			string cookie = null;
			HttpCookie httpCookie = request.Cookies.Get( COOKIE_NAME );
			if( httpCookie != null ) {
				cookie = httpCookie.Value;
			}

			string bearerToken = null;
			string bearerTokenHeader = request.Headers["Authorization"];
			if( bearerTokenHeader.StartsWith( AUTH_HEADER_PREFIX ) ) {
				bearerToken = bearerTokenHeader.Substring( AUTH_HEADER_PREFIX.Length );
			}

			string xsrfToken = request.Headers[XSRF_HEADER];

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
