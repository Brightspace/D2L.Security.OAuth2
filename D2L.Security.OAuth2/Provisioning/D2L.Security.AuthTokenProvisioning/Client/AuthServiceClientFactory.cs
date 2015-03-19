using System;
using System.Net.Http;
using D2L.Security.AuthTokenProvisioning.Client.Default;

namespace D2L.Security.AuthTokenProvisioning.Client {
	internal static class AuthServiceClientFactory {
		internal static IAuthServiceClient Create(
			Uri tokenProvisioningEndpoint
		) {
			return new AuthServiceClient(
				tokenProvisioningEndpoint: tokenProvisioningEndpoint
			);
		}

		internal static IAuthServiceClient Create(
			HttpClient httpClient,
			bool disposeHttpClient,
			Uri tokenProvisioningEndpoint
		) {
			return new AuthServiceClient(
				client: httpClient,
				disposeHttpClient: disposeHttpClient,
				tokenProvisioningEndpoint: tokenProvisioningEndpoint
			);
		}
	}
}
