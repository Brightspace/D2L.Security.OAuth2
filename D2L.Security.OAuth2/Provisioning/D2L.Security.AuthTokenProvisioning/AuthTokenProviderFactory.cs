using System;
using D2L.Security.AuthTokenProvisioning.Default;
using D2L.Security.AuthTokenProvisioning.Invocation;

namespace D2L.Security.AuthTokenProvisioning {
	public static class AuthTokenProviderFactory {
		
		public static IAuthTokenProvider Create( Uri tokenProvisioningEndpoint ) {
			IAuthServiceInvoker serviceInvoker = AuthServiceInvokerFactory.Create( tokenProvisioningEndpoint );
			return new AuthTokenProvider( serviceInvoker );
		}
	}
}
