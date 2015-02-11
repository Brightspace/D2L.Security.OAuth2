using System;
using D2L.Security.AuthTokenProvisioning.Invocation.Default;

namespace D2L.Security.AuthTokenProvisioning.Invocation {
	internal static class AuthServiceInvokerFactory {
		internal static IAuthServiceInvoker Create( Uri tokenProvisioningEndpoint ) {
			return new AuthServiceInvoker( tokenProvisioningEndpoint );
		}
	}
}
