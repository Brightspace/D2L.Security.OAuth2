using System;
using System.Net.Http;
using D2L.Security.AuthTokenProvisioning.Client;
using D2L.Security.AuthTokenProvisioning.Default;

namespace D2L.Security.AuthTokenProvisioning {
	public static class AuthTokenProviderFactory {

		public static IAuthTokenProvider Create(
			Uri tokenProvisioningEndpoint
		) {
			IAuthServiceClient client = AuthServiceClientFactory.Create(
				tokenProvisioningEndpoint: tokenProvisioningEndpoint
			);

			return new AuthTokenProvider( client );
		}
		
		public static IAuthTokenProvider Create(
			HttpClient httpClient,
			bool disposeHttpClient,
			Uri tokenProvisioningEndpoint
		) {
			IAuthServiceClient client = AuthServiceClientFactory.Create(
				httpClient: httpClient,
				disposeHttpClient: disposeHttpClient,
				tokenProvisioningEndpoint: tokenProvisioningEndpoint
			);
			return new AuthTokenProvider( client );
		}
	}
}
