using System;
using D2L.Security.AuthTokenValidation.Default;
using D2L.Security.AuthTokenValidation.TokenValidation;

namespace D2L.Security.AuthTokenValidation {

	public static class AuthTokenValidatorFactory {

		public static IAuthTokenValidator Create(
			Uri authServiceEndpoint
			) {

			IJWTValidator validator = JWTValidatorFactory.Create( authServiceEndpoint.ToString() );

			return new AuthTokenValidator(
				validator
				);
		}
	}
}
