using D2L.Security.AuthTokenValidation;

namespace D2L.Security.RequestAuthentication.Core.Default {
	internal sealed class CoreAuthenticator : ICoreAuthenticator {

		private readonly bool m_mustValidateXsrf;
		private readonly IAuthTokenValidator m_tokenValidator;

		internal CoreAuthenticator( 
			IAuthTokenValidator tokenValidator,
			bool mustValidateXsrf
			) {
			m_mustValidateXsrf = mustValidateXsrf;
			m_tokenValidator = tokenValidator;
		}

		AuthenticationResult ICoreAuthenticator.Authenticate( 
			string cookie, 
			string xsrfToken, 
			string bearerToken, 
			out ID2LPrincipal principal
			) {

			bool cookieExists = !string.IsNullOrEmpty( cookie );
			bool bearerTokenExists = !string.IsNullOrEmpty( bearerToken );

			if( !cookieExists && !bearerTokenExists ) {
				principal = null;
				return AuthenticationResult.Anonymous;
			}

			if( cookieExists && bearerTokenExists ) {
				principal = null;
				return AuthenticationResult.LocationConflict;
			}

			string token = cookieExists ? cookie : bearerToken;

			IGenericPrincipal claims;
			ValidationResult validationResult = m_tokenValidator.VerifyAndDecode( token, out claims );

			if( validationResult == ValidationResult.TokenExpired ) {
				principal = null;
				return AuthenticationResult.Expired;
			}

			bool isXsrfSafe = IsXsrfSafe( cookie, xsrfToken, claims );
			if( !isXsrfSafe ) {
				principal = null;
				return AuthenticationResult.XsrfMismatch;
			}
			
			principal = new D2LPrincipal();
			return AuthenticationResult.Success;
		}

		private bool IsXsrfSafe( string cookie, string xsrfToken, IGenericPrincipal claims ) {
			if( !m_mustValidateXsrf ) {
				return false;
			}

			bool isBrowserUser = !string.IsNullOrEmpty( cookie );
			bool xsrfTokensMatch = claims.XsrfToken == xsrfToken;
			if( isBrowserUser && !xsrfTokensMatch ) {
				return false;
			}

			return true;
		}
	}
}
