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
		
			var status = AuthenticationStatus.Success;

			bool cookieExists = !string.IsNullOrEmpty( cookie );
			bool bearerTokenExists = !string.IsNullOrEmpty( bearerToken );

			if( !cookieExists && !bearerTokenExists ) {
				status = AuthenticationStatus.Anonymous;
			}

			if( cookieExists && bearerTokenExists ) {
				status = AuthenticationStatus.LocationConflict;
			}

			string token = cookieExists ? cookie : bearerToken;
			
			ValidationResponse validationResponse = await m_accessTokenValidator.ValidateAsync(
				jwksEndpoint,
				bearerToken
			).ConfigureAwait( false );

			if( validationResponse.Status == ValidationStatus.Expired ) {
				status = AuthenticationStatus.Expired;
			}

			bool isXsrfSafe = IsXsrfSafe( cookie, xsrfToken, validationResponse.Token, authMode );
			if( !isXsrfSafe ) {
				status = AuthenticationStatus.XsrfMismatch;
			}

			AuthenticationResponse response;
			if( status != AuthenticationStatus.Success ) {

				// TODO When things go wrong like expired, xsrf mismatch, etc .. do we
				// still return the principal?   Or give them null?  
				// for now giving them null to match what was done before
				response = new AuthenticationResponse(
					status,
					principal: null
				);

			} else {
				ID2LPrincipal principal = new ValidatedTokenToD2LPrincipalAdapter( validationResponse.Token, token );
				response = new AuthenticationResponse(
					status,
					principal
				);
			}
			
			return response;
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
