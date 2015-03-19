using System;
using D2L.Security.AuthTokenProvisioning.Default;
using D2L.Security.AuthTokenProvisioning.Client;

namespace D2L.Security.AuthTokenProvisioning {
	public static class AuthTokenProviderFactory {
		
		public static IAuthTokenProvider Create( Uri tokenProvisioningEndpoint ) {
			IAuthServiceClient client = AuthServiceClientFactory.Create( tokenProvisioningEndpoint );
			return new AuthTokenProvider( client );
		}
	}
}
