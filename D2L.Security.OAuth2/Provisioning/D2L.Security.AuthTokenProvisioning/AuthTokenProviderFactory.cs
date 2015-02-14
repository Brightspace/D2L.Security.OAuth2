using System;
using System.Security.Cryptography.X509Certificates;
using D2L.Security.AuthTokenProvisioning.Default;
using D2L.Security.AuthTokenProvisioning.Invocation;

namespace D2L.Security.AuthTokenProvisioning {
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
