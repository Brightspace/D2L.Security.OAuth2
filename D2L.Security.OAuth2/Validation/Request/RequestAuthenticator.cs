using System;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web;
using D2L.Security.OAuth2.Principal;
using D2L.Security.OAuth2.Validation.AccessTokens;

namespace D2L.Security.OAuth2.Validation.Request {
	internal sealed class RequestAuthenticator : IRequestAuthenticator {

		private static readonly ID2LPrincipal ANONYMOUS_PRINCIPAL = new AnonymousPrincipal();

		private readonly IAccessTokenValidator m_accessTokenValidator;
		
		internal RequestAuthenticator( IAccessTokenValidator accessTokenValidator ) {
			m_accessTokenValidator = accessTokenValidator;
		}

		Task<AuthenticationResponse> IRequestAuthenticator.AuthenticateAsync(
			Uri authEndpoint,
			HttpRequestMessage request,
			AuthenticationMode authMode
		) {
			string cookie = request.GetCookieValue();
			string bearerToken = request.GetBearerTokenValue();
			string xsrfToken = request.GetXsrfValue();

			return AuthenticateHelper( authEndpoint, cookie, xsrfToken, bearerToken, authMode );
		}

		Task<AuthenticationResponse> IRequestAuthenticator.AuthenticateAsync(
			Uri authEndpoint,
			HttpRequest request,
			AuthenticationMode authMode
		) {
			string cookie = request.GetCookieValue();
			string bearerToken = request.GetBearerTokenValue();
			string xsrfToken = request.GetXsrfValue();

			return AuthenticateHelper( authEndpoint, cookie, xsrfToken, bearerToken, authMode );
		}

		private async Task<AuthenticationResponse> AuthenticateHelper(
			Uri authEndpoint,
			string cookie,
			string xsrfToken,
			string bearerToken,
			AuthenticationMode authMode
		) {
		
			bool cookieExists = !string.IsNullOrEmpty( cookie );
			bool bearerTokenExists = !string.IsNullOrEmpty( bearerToken );

			if( !cookieExists && !bearerTokenExists ) {
				return new AuthenticationResponse(
					AuthenticationStatus.Anonymous,
					principal: ANONYMOUS_PRINCIPAL
				);
			}

			if( cookieExists && bearerTokenExists ) {
				return new AuthenticationResponse(
					AuthenticationStatus.LocationConflict,
					principal: null
				);
			}

			string token = cookieExists ? cookie : bearerToken;
			
			IValidationResponse validationResponse = await m_accessTokenValidator.ValidateAsync(
				authEndpoint,
				token
			).SafeAsync();

			if( validationResponse.Status == ValidationStatus.Expired ) {
				return new AuthenticationResponse(
					AuthenticationStatus.Expired,
					principal: null
				);
			}

			// TODO .. we should consider doing the xsrf check without validating the jwt
			bool isXsrfSafe = IsXsrfSafe( cookie, xsrfToken, validationResponse.AccessToken, authMode );
			if( !isXsrfSafe ) {
				return new AuthenticationResponse(
					AuthenticationStatus.XsrfMismatch,
					principal: null
				);
			}

			if( validationResponse.Status == ValidationStatus.Success ) {
				ID2LPrincipal principal = new D2LPrincipal( validationResponse.AccessToken );
				return new AuthenticationResponse(
					AuthenticationStatus.Success,
					principal
				);
			}

			throw new Exception( "Unknown validation status: " + validationResponse.Status );
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
