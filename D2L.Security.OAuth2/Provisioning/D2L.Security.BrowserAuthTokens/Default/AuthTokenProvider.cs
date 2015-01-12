using System;

namespace D2L.Security.BrowserAuthTokens.Default {
	public sealed class AuthTokenProvider : IAuthTokenProvider {
		public string GetTokenForUser( string tenantId, long userId, string xsrfToken, long duration ) {
			throw new NotImplementedException();
		}
	}
}