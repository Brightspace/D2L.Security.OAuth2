using D2L.Security.AuthTokenValidation.PublicKeys;
using D2L.Security.AuthTokenValidation.TokenValidation.Default;

namespace D2L.Security.AuthTokenValidation.TokenValidation {
	internal static class JWTValidatorFactory {

		private static readonly IJWTValidator Instance =
			new JWTValidator( PublicKeyProviderFactory.Create() );

		internal static IJWTValidator Create() {
			return Instance;
		}
	}
}
