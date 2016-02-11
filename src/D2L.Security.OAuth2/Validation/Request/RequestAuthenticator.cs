using System;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web;
using D2L.Security.OAuth2.Principal;
using D2L.Security.OAuth2.Validation.AccessTokens;
using D2L.Security.OAuth2.Validation.Exceptions;

namespace D2L.Security.OAuth2.Validation.Request {
	internal sealed class RequestAuthenticator : IRequestAuthenticator {

		private static readonly ID2LPrincipal ANONYMOUS_PRINCIPAL = new AnonymousPrincipal();

		private readonly IAccessTokenValidator m_accessTokenValidator;
		
		internal RequestAuthenticator( IAccessTokenValidator accessTokenValidator ) {
			m_accessTokenValidator = accessTokenValidator;
		}

		Task<ID2LPrincipal> IRequestAuthenticator.AuthenticateAsync(
			HttpRequestMessage request,
			AuthenticationMode authMode
		) {
			string cookie = request.GetCookieValue();
			string bearerToken = request.GetBearerTokenValue();
			string xsrfToken = request.GetXsrfValue();

			return AuthenticateHelper( cookie, xsrfToken, bearerToken, authMode );
		}

		Task<ID2LPrincipal> IRequestAuthenticator.AuthenticateAsync(
			HttpRequest request,
			AuthenticationMode authMode
		) {
			string cookie = request.GetCookieValue();
			string bearerToken = request.GetBearerTokenValue();
			string xsrfToken = request.GetXsrfValue();

			return AuthenticateHelper( cookie, xsrfToken, bearerToken, authMode );
		}

		private async Task<ID2LPrincipal> AuthenticateHelper(
			string cookie,
			string xsrfToken,
			string bearerToken,
			AuthenticationMode authMode
		) {
		
			bool cookieExists = !string.IsNullOrEmpty( cookie );
			bool bearerTokenExists = !string.IsNullOrEmpty( bearerToken );

			if( !cookieExists && !bearerTokenExists ) {
				return ANONYMOUS_PRINCIPAL;
			}

			string token = bearerTokenExists ? bearerToken : cookie;
			
			IAccessToken accessToken = await m_accessTokenValidator
				.ValidateAsync( token )
				.SafeAsync();

			// TODO .. we should consider doing the xsrf check without validating the jwt
			bool isXsrfSafe = IsXsrfSafe( cookie, xsrfToken, accessToken, authMode );
			if( !isXsrfSafe ) {
				throw new XsrfException( "Request is lacking XSRF protection" );
			}

			ID2LPrincipal principal = new D2LPrincipal( accessToken );

			return principal;
		}

		private bool IsXsrfSafe(
			string cookie,
			string xsrfToken,
			IAccessToken accessToken,
			AuthenticationMode authMode
		) {

			if( authMode == AuthenticationMode.SkipXsrfValidation ) {
				return true;
			}

			bool isBrowserUser = !string.IsNullOrEmpty( cookie );
			if( !isBrowserUser ) {
				return true;
			}

			// we must now validate that the xsrf tokens match

			string xsrfTokenFromAccessToken = accessToken.GetXsrfToken();

			bool xsrfTokensEqual = xsrfTokenFromAccessToken == xsrfToken;
			bool xsrfTokenContainsValue = !string.IsNullOrEmpty( xsrfToken );

			if( !xsrfTokensEqual || !xsrfTokenContainsValue ) {
				return false;
			}

			return true;
		}
	}
}
