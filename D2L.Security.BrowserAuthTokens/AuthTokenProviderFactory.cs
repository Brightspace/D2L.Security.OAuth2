using System;
using System.Security.Cryptography.X509Certificates;
using D2L.Security.BrowserAuthTokens.Default;

namespace D2L.Security.BrowserAuthTokens {
	public static class AuthTokenProviderFactory {
		
		public static IAuthTokenProvider Create(
			X509Certificate2 certificate,
			Uri authServiceEndpoint
			) {

			return new AuthTokenProvider( certificate );
		}
	}
}
