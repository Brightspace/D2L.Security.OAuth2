using D2L.Security.AuthTokenValidation.PublicKeys;
using D2L.Security.AuthTokenValidation.TokenValidation.Default;

namespace D2L.Security.AuthTokenValidation.TokenValidation {
	internal static class JWTValidatorFactory {

		internal static IJWTValidator Create( string authority ) {
			IPublicKeyProvider keyProvider = PublicKeyProviderFactory.Create( authority );
			IJWTValidator validator = new JWTValidator( keyProvider );
			return validator;
		}
	}
}
