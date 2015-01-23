using D2L.Security.AuthTokenValidation;

namespace D2L.Security.RequestAuthentication.Core.Default {
	internal sealed class CoreAuthenticator : ICoreAuthenticator {

		private readonly IAuthTokenValidator m_tokenValidator;

		internal CoreAuthenticator( IAuthTokenValidator tokenValidator ) {
			m_tokenValidator = tokenValidator;
		}

		AuthenticationResult ICoreAuthenticator.Authenticate( 
			string cookie, 
			string xsrfHeader, 
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

			bool isBrowserUser = cookieExists;
			string token = cookieExists ? cookie : bearerToken;

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
					return AuthenticationResult.XsrfMismatch;
				}

				xsrfSafe = true;
			}

			principal = new D2LPrincipal( xsrfSafe );
			return AuthenticationResult.Success;
		}
	}
}
