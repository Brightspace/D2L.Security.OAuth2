using System;
using D2L.Security.AuthTokenValidation;
using D2L.Security.RequestAuthentication.Default;

namespace D2L.Security.RequestAuthentication {
	public static class RequestAuthenticatorFactory {

		public static IRequestAuthenticator Create( IAuthTokenValidator tokenValidator ) {
			return new RequestAuthenticator( tokenValidator );
		}

		public static IRequestAuthenticator Create( Uri authServiceEndpoint ) {
			IAuthTokenValidator tokenValidator = AuthTokenValidatorFactory.Create( authServiceEndpoint );
			return new RequestAuthenticator( tokenValidator );
		}
	}
}
