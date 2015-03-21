using System;
using D2L.Security.OAuth2.Validation.Token.Default;
using D2L.Security.OAuth2.Validation.Token.JwtValidation;

namespace D2L.Security.OAuth2.Validation.Token {

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
