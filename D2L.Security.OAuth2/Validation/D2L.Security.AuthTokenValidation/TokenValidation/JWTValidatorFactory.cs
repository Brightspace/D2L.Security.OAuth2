using System.IdentityModel.Tokens;
using D2L.Security.AuthTokenValidation.PublicKeys;
using D2L.Security.AuthTokenValidation.TokenValidation.Default;

namespace D2L.Security.AuthTokenValidation.TokenValidation {
	internal static class JWTValidatorFactory {

		internal static IJWTValidator Create( string authority ) {
			IPublicKeyProvider keyProvider = PublicKeyProviderFactory.Create( authority );
			ISecurityTokenValidator tokenHandler = JWTHelper.CreateTokenHandler();

			IJWTValidator validator = new JWTValidator( keyProvider, tokenHandler );
			return validator;
		}
	}
}
