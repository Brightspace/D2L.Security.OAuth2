using System;
using D2L.Security.OAuth2.Validation.Jwks;
using D2L.Security.OAuth2.Validation.Jwks.Data;
using D2L.Security.OAuth2.Validation.Request.Default;

namespace D2L.Security.OAuth2.Validation.Request {
	public static class RequestAuthenticatorFactory {
		
		public static IRequestAuthenticator Create() {
			IJwksProvider jwksProvider = new JwksProvider();
			ISecurityTokenProvider tokenProvider = new SecurityTokenProvider( jwksProvider );
			IAccessTokenValidator validator = new AccessTokenValidator( tokenProvider );
			IRequestAuthenticator authenticator = new RequestAuthenticator( validator );
			return authenticator;
		}

	}
}
