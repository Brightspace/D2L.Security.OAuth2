using System;

namespace D2L.Security.AuthTokenValidation.Default {

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
