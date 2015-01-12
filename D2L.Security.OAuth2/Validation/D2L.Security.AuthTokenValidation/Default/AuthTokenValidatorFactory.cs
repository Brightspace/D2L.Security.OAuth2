using System;
using D2L.Security.AuthTokenValidation.TokenValidation;

namespace D2L.Security.AuthTokenValidation.Default {

	public sealed class AuthTokenValidatorFactory : IAuthTokenValidatorFactory {

		public IAuthTokenValidator Create(
			Uri authServiceEndpoint
			) {

			IJWTValidator validator = JWTValidatorFactory.Create( authServiceEndpoint.ToString() );

			return new AuthTokenValidator(
				validator
				);
		}
	}
}
