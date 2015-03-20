using System;
using D2L.Security.AuthTokenValidation.Default;
using D2L.Security.AuthTokenValidation.JwtValidation;

namespace D2L.Security.AuthTokenValidation {

	public static class AuthTokenValidatorFactory {

		public static IAuthTokenValidator Create(
			Uri authServiceEndpoint
			) {

			IJwtValidator validator = JwtValidatorFactory.Create( authServiceEndpoint );

			return new AuthTokenValidator(
				validator
				);
		}
	}
}
