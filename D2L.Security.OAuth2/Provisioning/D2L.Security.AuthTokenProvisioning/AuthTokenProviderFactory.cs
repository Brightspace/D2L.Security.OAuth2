using System;
using System.IdentityModel.Tokens;
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
			SigningCredentials signingCredentials = new X509SigningCredentials( certificate );

			return Create( signingCredentials, tokenProvisioningEndpoint );
		}

		public static IAuthTokenProvider Create(
			SigningCredentials signingCredentials,
			Uri tokenProvisioningEndpoint
			) {

			IAuthServiceInvoker serviceInvoker = AuthServiceInvokerFactory.Create( tokenProvisioningEndpoint );
			return new AuthTokenProvider( signingCredentials, serviceInvoker );
		}
	}
}
