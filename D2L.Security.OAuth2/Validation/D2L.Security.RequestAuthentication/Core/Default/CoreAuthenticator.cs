using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
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
