using System;
using D2L.Security.AuthTokenValidation.Default;

namespace D2L.Security.AuthTokenValidation {

	public sealed class AuthTokenValidatorFactory : IAuthTokenValidatorFactory {

		public IAuthTokenValidator Create(
			Uri authServiceEndpoint
			) {
			return new AuthTokenValidator(
				new AuthServerPublicKeyProvider( authServiceEndpoint )
				);
		}
	}
}
