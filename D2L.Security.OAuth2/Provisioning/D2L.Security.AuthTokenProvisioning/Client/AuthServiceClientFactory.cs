using System;
using D2L.Security.AuthTokenProvisioning.Client.Default;

namespace D2L.Security.AuthTokenProvisioning.Client {
	internal static class AuthServiceClientFactory {
		internal static IAuthServiceClient Create( Uri tokenProvisioningEndpoint ) {
			return new AuthServiceClient( tokenProvisioningEndpoint );
		}
	}
}
