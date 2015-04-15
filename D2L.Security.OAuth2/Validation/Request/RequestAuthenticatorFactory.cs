using System;
using D2L.Security.OAuth2.Caching;
using D2L.Security.OAuth2.Validation.AccessTokens;

namespace D2L.Security.OAuth2.Validation.Request {
	public static class RequestAuthenticatorFactory {
		
		public static IRequestAuthenticator Create( ICache cache = null ) {
			if( cache == null ) {
				cache = new NullCache();
			}

			IAccessTokenValidator validator = AccessTokenValidatorFactory.Create( cache );
			IRequestAuthenticator authenticator = new RequestAuthenticator( validator );
			return authenticator;
		}

	}
}
