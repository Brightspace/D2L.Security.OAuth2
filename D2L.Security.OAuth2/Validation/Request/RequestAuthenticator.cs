using System;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web;
using D2L.Security.OAuth2.Validation.AccessTokens;

namespace D2L.Security.OAuth2.Validation.Request {
	internal sealed class RequestAuthenticator : IRequestAuthenticator {

		private readonly IAccessTokenValidator m_accessTokenValidator;
		
		internal RequestAuthenticator( IAccessTokenValidator accessTokenValidator ) {
			m_accessTokenValidator = accessTokenValidator;
		}

		Task<AuthenticationResponse> IRequestAuthenticator.AuthenticateAsync(
			Uri jwksEndpoint,
			HttpRequestMessage request,
			AuthenticationMode authMode
		) {
			string cookie = request.GetCookieValue();
			string bearerToken = request.GetBearerTokenValue();
			string xsrfToken = request.GetXsrfValue();

			return AuthenticateHelper( jwksEndpoint, cookie, xsrfToken, bearerToken, authMode );
		}

		Task<AuthenticationResponse> IRequestAuthenticator.AuthenticateAsync(
			Uri jwksEndpoint,
			HttpRequest request,
			AuthenticationMode authMode
		) {
			string cookie = request.GetCookieValue();
			string bearerToken = request.GetBearerTokenValue();
			string xsrfToken = request.GetXsrfValue();

			return AuthenticateHelper( jwksEndpoint, cookie, xsrfToken, bearerToken, authMode );
		}

		private async Task<AuthenticationResponse> AuthenticateHelper(
			Uri jwksEndpoint,
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
					principal: null
				);
			}

			if( cookieExists && bearerTokenExists ) {
				return new AuthenticationResponse(
					AuthenticationStatus.LocationConflict,
					principal: null
				);
			}

			string token = cookieExists ? cookie : bearerToken;
			
			ValidationResponse validationResponse = await m_accessTokenValidator.ValidateAsync(
				jwksEndpoint,
				token
			).SafeAsync();

			if( validationResponse.Status == ValidationStatus.Expired ) {
				return new AuthenticationResponse(
					AuthenticationStatus.Expired,
					principal: null
				);
			}

			// TODO .. we should consider doing the xsrf check without validating the jwt
			bool isXsrfSafe = IsXsrfSafe( cookie, xsrfToken, validationResponse.Token, authMode );
			if( !isXsrfSafe ) {
				return new AuthenticationResponse(
					AuthenticationStatus.XsrfMismatch,
					principal: null
				);
			}

			if( validationResponse.Status == ValidationStatus.Success ) {
				ID2LPrincipal principal = new ValidatedTokenToD2LPrincipalAdapter( validationResponse.Token, token );
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
			IValidatedToken validatedToken,
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

			string xsrfTokenFromValidatedToken = validatedToken.GetXsrfToken();

			bool xsrfTokensEqual = xsrfTokenFromValidatedToken == xsrfToken;
			bool xsrfTokenContainsValue = !string.IsNullOrEmpty( xsrfToken );

			if( !xsrfTokensEqual || !xsrfTokenContainsValue ) {
				return false;
			}

			return true;
		}
	}
}
