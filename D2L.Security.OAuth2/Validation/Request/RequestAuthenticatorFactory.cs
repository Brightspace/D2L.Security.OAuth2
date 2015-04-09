using System;
using D2L.Security.OAuth2.Caching;
using D2L.Security.OAuth2.Validation.Jwks;
using D2L.Security.OAuth2.Validation.Jwks.Data;
using D2L.Security.OAuth2.Validation.Request.Default;

namespace D2L.Security.OAuth2.Validation.Request {
	public static class RequestAuthenticatorFactory {
		
		public static IRequestAuthenticator Create( ICache cache = null ) {
			if( cache == null ) {
				cache = new NullCache();
			}

			IJwksProvider jwksProvider = new JwksProvider();
			IJwksProvider cacheJwksProvider = new CachedJwksProvider( cache, jwksProvider );
			
			ISecurityTokenProvider tokenProvider = new SecurityTokenProvider( cacheJwksProvider );
			IAccessTokenValidator validator = new AccessTokenValidator( tokenProvider );
			IRequestAuthenticator authenticator = new RequestAuthenticator( validator );
			return authenticator;
		}

	}
}
