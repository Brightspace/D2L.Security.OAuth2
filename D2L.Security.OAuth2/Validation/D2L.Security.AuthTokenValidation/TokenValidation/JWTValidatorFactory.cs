using D2L.Security.AuthTokenValidation.PublicKeys;
using D2L.Security.AuthTokenValidation.TokenValidation.Default;

namespace D2L.Security.AuthTokenValidation.TokenValidation {
	internal static class JWTValidatorFactory {

		private static object Lock = new object();
		private static IJWTValidator Instance;

		internal static IJWTValidator Create( string authority ) {
			if( Instance == null ) {
				lock( Lock ) {
					if( Instance == null ) {
						Instance = new JWTValidator( PublicKeyProviderFactory.Create( authority ) );
					}
				}
			}
			
			return Instance;
		}
	}
}
