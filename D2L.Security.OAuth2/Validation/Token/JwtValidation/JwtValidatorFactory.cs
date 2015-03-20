using System;
using System.IdentityModel.Tokens;
using D2L.Security.AuthTokenValidation.PublicKeys;
using D2L.Security.AuthTokenValidation.JwtValidation.Default;

namespace D2L.Security.AuthTokenValidation.JwtValidation {
	internal static class JwtValidatorFactory {

		internal static IJwtValidator Create( Uri authority ) {
			IPublicKeyProvider keyProvider = PublicKeyProviderFactory.Create( authority );
			ISecurityTokenValidator tokenHandler = JwtHelper.CreateTokenHandler();

			IJwtValidator validator = new JwtValidator( keyProvider, tokenHandler );
			return validator;
		}
	}
}
