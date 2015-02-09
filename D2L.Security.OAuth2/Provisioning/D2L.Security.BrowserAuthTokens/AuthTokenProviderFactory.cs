using System;
using System.Security.Cryptography.X509Certificates;
using D2L.Security.BrowserAuthTokens.Default;
using D2L.Security.BrowserAuthTokens.Invocation;

namespace D2L.Security.BrowserAuthTokens {
	public static class AuthTokenProviderFactory {
		
		public static IAuthTokenProvider Create(
			X509Certificate2 certificate,
			Uri tokenProvisioningEndpoint
			) {

			IAuthServiceInvoker serviceInvoker = AuthServiceInvokerFactory.Create( tokenProvisioningEndpoint );
			return new AuthTokenProvider( certificate, serviceInvoker );
		}
	}
}
