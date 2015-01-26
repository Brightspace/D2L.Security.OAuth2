using System;
using D2L.Security.AuthTokenValidation;
using D2L.Security.RequestAuthentication.Core;
using D2L.Security.RequestAuthentication.Default;

namespace D2L.Security.RequestAuthentication {
	public static class RequestAuthenticatorFactory {

		public static IRequestAuthenticator Create( Uri authServiceEndpoint, bool mustValidateXsrf ) {
			IAuthTokenValidator tokenValidator = AuthTokenValidatorFactory.Create( authServiceEndpoint );
			ICoreAuthenticator coreAuthenticator = CoreAuthenticatorFactory.Create( tokenValidator, mustValidateXsrf );
			return new RequestAuthenticator( coreAuthenticator );
		}
	}
}
